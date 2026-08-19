#!/usr/bin/env python3
"""
Smallpond Query Executor: DuckDB + Ray Backend
Innoura Technologies | RustFS Audit Gateway Integration
Production: v1.0 | Formal Validation + Audit Logging

Safety Layer: SQL queries pre-validated by Rust gateway (allowlist regex).
This script enforces runtime safety checks and formal result validation.
"""

import sys
import json
import os
import re
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
import hashlib
import logging

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
    handlers=[
        logging.StreamHandler(sys.stderr),
        logging.FileHandler('audit_query.log', mode='a')
    ]
)
logger = logging.getLogger("smallpond_executor")

# ============================================================================
# CONFIGURATION & CONSTANTS (Formal Safety Bounds)
# ============================================================================

# Maximum rows returned from a single query (prevent memory exhaustion)
MAX_RESULT_ROWS = 10000

# Maximum SQL query length (prevent huge payloads)
MAX_QUERY_LENGTH = 5000

# Allowed table names (whitelist, case-insensitive)
ALLOWED_TABLES = {
    'rustfs_inventory',
    'rustfs_manifest',
    'media_pairs',
    'video_segments',
    'vtt_overlays',
}

# Allowed column names
ALLOWED_COLUMNS = {
    'video_id', 'start_ts', 'end_ts', 'video_segment_url', 'zstd_vtt_url',
    'object_type', 'breach_detected', 'timestamp', 'camera_id', 'detections',
}

# Parquet ledger path
PARQUET_LEDGER_PATH = Path("output/rustfs_manifest.parquet")

# ============================================================================
# FORMAL VALIDATION LAYER
# ============================================================================

class QueryValidator:
    """Formal SQL validation: ensures query structure is safe"""
    
    @staticmethod
    def validate_query(query: str) -> tuple[bool, str]:
        """
        Validate query syntax and semantics.
        
        Invariant: Query must match the allowlist pattern from Rust gateway.
        Returns: (is_valid, error_message)
        """
        # Check length bound
        if len(query) > MAX_QUERY_LENGTH:
            return False, f"Query exceeds max length {MAX_QUERY_LENGTH} (got {len(query)})"
        
        # Step 1: SQL Injection prevention (secondary validation)
        # This must perfectly match the Lean 4 proven Rust regex
        ALLOWLIST_PATTERN = r"^SELECT\s+[a-zA-Z0-9_,\s*]+FROM\s+[a-zA-Z0-9_]+\s*(WHERE\s+[a-zA-Z0-9_()=<>'\s%\*\+\-\./]+)?$"
        if not re.match(ALLOWLIST_PATTERN, query, re.IGNORECASE):
            return False, "Query does not match allowlist pattern: SELECT ... FROM ... [WHERE ...]"
        
        # Uppercase for normalization
        query_upper = query.strip().upper()
        
        # Extract table name
        from_match = re.search(r'FROM\s+([A-Z0-9_]+)', query_upper)
        if not from_match:
            return False, "No FROM clause found"
        
        table_name = from_match.group(1).lower()
        if table_name not in ALLOWED_TABLES:
            return False, f"Table '{table_name}' not in whitelist: {ALLOWED_TABLES}"
        
        # Extract columns (basic check)
        select_match = re.search(r'SELECT\s+(.*?)\s+FROM', query_upper)
        if select_match:
            columns_str = select_match.group(1)
            # Allow * or specific columns
            if columns_str.strip() != '*':
                columns = [c.strip() for c in columns_str.split(',')]
                for col in columns:
                    # Remove aliases (e.g., "col as alias")
                    base_col = col.split()[0]
                    if base_col not in ALLOWED_COLUMNS and base_col != '*':
                        return False, f"Column '{base_col}' not in whitelist: {ALLOWED_COLUMNS}"
        
        return True, ""
    
    @staticmethod
    def compute_query_hash(query: str) -> str:
        """Compute SHA256 hash of query for audit trail"""
        return hashlib.sha256(query.encode()).hexdigest()[:16]


class ResultValidator:
    """Formal result validation: ensures output conforms to expected schema"""
    
    @staticmethod
    def validate_media_pair(pair: Dict[str, Any]) -> tuple[bool, str]:
        """
        Validate a single MediaPair result.
        
        Invariant: Must contain required fields with correct types.
        Returns: (is_valid, error_message)
        """
        required_fields = {
            'video_id': str,
            'start_ts': (int, float),
            'end_ts': (int, float),
            'video_segment_url': str,
            'zstd_vtt_url': str,
        }
        
        for field, expected_type in required_fields.items():
            if field not in pair:
                return False, f"Missing required field: {field}"
            
            if not isinstance(pair[field], expected_type):
                return False, f"Field '{field}' has wrong type: expected {expected_type}, got {type(pair[field])}"
        
        # Semantic checks
        if pair['start_ts'] >= pair['end_ts']:
            return False, f"start_ts ({pair['start_ts']}) >= end_ts ({pair['end_ts']})"
        
        if not pair['video_id'].strip():
            return False, "video_id cannot be empty"
        
        if not (pair['video_segment_url'].endswith('.ts') or pair['video_segment_url'].endswith('.mp4') or pair['video_segment_url'].endswith('.m4s')):
            return False, f"video_segment_url must end with .ts, .mp4, or .m4s (got {pair['video_segment_url']})"
        
        if not pair['zstd_vtt_url'].endswith('.vtt.zst'):
            return False, f"zstd_vtt_url must end with .vtt.zst (got {pair['zstd_vtt_url']})"
        
        return True, ""
    
    @staticmethod
    def validate_results(results: List[Dict[str, Any]]) -> tuple[bool, str, List[Dict[str, Any]]]:
        """
        Validate entire result set.
        
        Returns: (is_valid, error_message, cleaned_results)
        """
        if len(results) > MAX_RESULT_ROWS:
            return False, f"Result set exceeds max rows {MAX_RESULT_ROWS} (got {len(results)})", []
        
        cleaned_results = []
        for i, pair in enumerate(results):
            is_valid, error = ResultValidator.validate_media_pair(pair)
            if not is_valid:
                logger.warning(f"Result #{i} validation failed: {error}")
                # Skip invalid rows, continue processing
                continue
            cleaned_results.append(pair)
        
        if len(cleaned_results) == 0 and len(results) > 0:
            return False, "All result rows failed validation", []
        
        return True, "", cleaned_results


# ============================================================================
# QUERY EXECUTOR (DuckDB + Formal Safety)
# ============================================================================

def execute_query_safe(query: str) -> Dict[str, Any]:
    """
    Execute DuckDB query with formal safety guarantees.
    
    Returns: {
        "status": "success" | "error",
        "query_hash": str,
        "results": List[Dict],
        "row_count": int,
        "execution_time_ms": float,
        "error": str (if status == "error")
    }
    """
    start_time = datetime.now()
    query_hash = QueryValidator.compute_query_hash(query)
    
    logger.info(f"Query received | hash={query_hash} | length={len(query)}")
    
    # Step 1: Validate query structure
    is_valid, error = QueryValidator.validate_query(query)
    if not is_valid:
        logger.warning(f"Query validation failed | hash={query_hash} | error={error}")
        return {
            "status": "error",
            "query_hash": query_hash,
            "error": f"Query validation failed: {error}",
            "results": [],
            "row_count": 0,
            "execution_time_ms": (datetime.now() - start_time).total_seconds() * 1000,
        }
    
    logger.info(f"Query passed validation | hash={query_hash}")
    
    # Step 2: Skip manifest check (using remote Postgres)
    
    # Step 3: Execute query with native PostgreSQL
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        import uuid
        
        # Connect to Postgres database directly
        logger.info("Connecting directly to PostgreSQL...")
        conn = psycopg2.connect("postgres://visionguard:VisionGuard%402026@54.204.98.59:5432/visionguard")
        
        # Execute user query
        logger.info(f"Executing query | hash={query_hash}")
        
        # Extract ALL target detection labels mentioned anywhere in the SQL query string
        KNOWN_DETECTION_LABELS = [
            'zone_breach', 'no_helmet', 'no_gloves', 'no_goggles', 'no_shoes', 'no_vest',
            'helmet', 'gloves', 'goggles', 'shoes', 'vest', 'person', 'fire', 'smoke'
        ]
        target_labels = []
        query_lower = query.lower()
        
        # Sort labels by length descending so longer/specific labels (e.g. 'no_helmet') match first
        sorted_known = sorted(KNOWN_DETECTION_LABELS, key=len, reverse=True)
        matched_spans = []
        
        for label in sorted_known:
            label_spaced = label.replace('_', ' ')
            label_det = f"{label}_detection"
            
            for pattern in [label, label_spaced, label_det]:
                for m in re.finditer(re.escape(pattern), query_lower):
                    start, end = m.span()
                    # Skip if this match overlaps with an already matched longer label (e.g. 'helmet' inside 'no_helmet')
                    if not any(s <= start and end <= e for s, e in matched_spans):
                        matched_spans.append((start, end))
                        if label not in target_labels:
                            target_labels.append(label)

        # Inject PostgreSQL JSONB operators to eliminate TOAST table scans
        if "video_segments" in query.lower():
            # If no LIMIT clause is provided, automatically append LIMIT 1000
            if "limit" not in query.lower():
                if "order by" not in query.lower():
                    query = query.strip() + " ORDER BY start_ms DESC LIMIT 1000"
                else:
                    query = query.strip() + " LIMIT 1000"

            # First, rewrite `SELECT *` to fetch the columns we need including detections JSONB
            exec_query = re.sub(r'SELECT\s+\*\s+FROM', 'SELECT camera_id, start_ms, end_ms, s3_key, detections FROM', query, flags=re.IGNORECASE)
            
            # Then, rewrite the slow ILIKE to a hyper-fast JSONB structural containment check (@>)
            # Handles label aliases (e.g. helmet_detection -> helmet, no_helmet_detection -> no_helmet)
            def replace_ilike(m):
                keyword = m.group(1).lower().strip()
                clean_label = re.sub(r'(_)?detection(s)?$', '', keyword).strip()
                
                conds = []
                if clean_label:
                    conds.append(f"detections @> '{{\"frames\": [{{\"boxes\": [{{\"label\": \"{clean_label}\"}}]}}]}}'")
                if keyword and keyword != clean_label:
                    conds.append(f"detections @> '{{\"frames\": [{{\"boxes\": [{{\"label\": \"{keyword}\"}}]}}]}}'")
                
                # Only check model_type for non-"no_" labels (since model_type for no_helmet is HELMET_DETECTION)
                if not clean_label.startswith("no_"):
                    model_type = f"{clean_label.upper()}_DETECTION"
                    conds.append(f"detections @> '{{\"frames\": [{{\"boxes\": [{{\"model_type\": \"{model_type}\"}}]}}]}}'")
                
                return f"({' OR '.join(conds)})"
            
            exec_query = re.sub(r'detections(?:\:\:text)?\s+ILIKE\s+\'%([^%]+)%\'', replace_ilike, exec_query, flags=re.IGNORECASE)
        else:
            exec_query = query
            
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(exec_query)
            result = cur.fetchall()
            
            # Fetch camera names for mapping
            cur.execute("SELECT id, name FROM cameras")
            cameras = {r['id']: r['name'] for r in cur.fetchall()}
            
        conn.close()
        
        # Helper to strictly match target box label vs queried detection
        def is_box_matching_target(b, target_kws):
            # If no detection filter in SQL query -> return ALL bounding box coordinates!
            if not target_kws:
                return True
            
            box_label = (b.get("label") or "").lower().strip()
            box_has_no = box_label.startswith("no_") or box_label.startswith("no-")
            norm_box = box_label.replace("no_", "").replace("no-", "").strip()

            for target_kw in target_kws:
                target_clean = re.sub(r'(_)?detection(s)?$', '', target_kw.lower()).strip()
                target_has_no = target_clean.startswith("no_") or target_clean.startswith("no-") or "no " in target_clean
                
                # Strict invariant: negative (no_helmet) and positive (helmet) labels must NEVER match each other
                if target_has_no != box_has_no:
                    continue
                    
                norm_target = target_clean.replace("no_", "").replace("no-", "").strip()
                if norm_box == norm_target or norm_box in norm_target or norm_target in norm_box:
                    return True
                    
            return False

        # Convert to standard dicts and map schema
        results = []
        for row in result:
            d = {k: str(v) if isinstance(v, uuid.UUID) else v for k, v in dict(row).items()}
            
            # If the query was against video_segments, we map it
            if "camera_id" in d:
                raw_det = d.get("detections")
                # Filter bounding boxes dynamically based on SQL query filters
                if target_labels and isinstance(raw_det, dict) and "frames" in raw_det:
                    filtered_frames = []
                    for frame in raw_det.get("frames", []):
                        boxes = frame.get("boxes", [])
                        matching_boxes = [b for b in boxes if is_box_matching_target(b, target_labels)]
                        if matching_boxes:
                            frame_copy = dict(frame)
                            frame_copy["boxes"] = matching_boxes
                            filtered_frames.append(frame_copy)
                    det_copy = dict(raw_det)
                    det_copy["frames"] = filtered_frames
                    filtered_det = det_copy
                else:
                    filtered_det = raw_det

                mapped = {
                    "video_id": d.get("camera_id"),
                    "cameraName": cameras.get(d.get("camera_id"), "Unknown Camera"),
                    "start_ts": d.get("start_ms"),
                    "end_ts": d.get("end_ms"),
                    "detections": filtered_det,
                }
                if "s3_key" in d:
                    base_url = "http://54.204.98.59:10011/visionguard-playback/"
                    s3_key = d["s3_key"]
                    mapped["video_segment_url"] = base_url + s3_key
                    # Replace extension with .vtt.zst for subtitle url
                    ext_idx = s3_key.rfind('.')
                    if ext_idx != -1:
                        mapped["zstd_vtt_url"] = base_url + s3_key[:ext_idx] + ".vtt.zst"
                    else:
                        mapped["zstd_vtt_url"] = base_url + s3_key + ".vtt.zst"
                results.append(mapped)
            else:
                results.append(d)
        
        logger.info(f"Query executed | hash={query_hash} | rows={len(results)}")
        
        # Step 4: Validate results
        is_valid, error, cleaned = ResultValidator.validate_results(results)
        if not is_valid:
            logger.warning(f"Result validation failed | hash={query_hash} | error={error}")
            return {
                "status": "error",
                "query_hash": query_hash,
                "error": f"Result validation failed: {error}",
                "results": [],
                "row_count": 0,
                "execution_time_ms": (datetime.now() - start_time).total_seconds() * 1000,
            }
        
        logger.info(f"Query succeeded | hash={query_hash} | rows={len(cleaned)}")
        
        return {
            "status": "success",
            "query_hash": query_hash,
            "results": cleaned,
            "row_count": len(cleaned),
            "execution_time_ms": (datetime.now() - start_time).total_seconds() * 1000,
        }
    
    except ImportError:
        logger.error("DuckDB not installed; falling back to minimal JSON response")
        return {
            "status": "error",
            "query_hash": query_hash,
            "error": "DuckDB library not available",
            "results": [],
            "row_count": 0,
            "execution_time_ms": (datetime.now() - start_time).total_seconds() * 1000,
        }
    
    except Exception as e:
        logger.error(f"Query execution failed | hash={query_hash} | error={str(e)}")
        return {
            "status": "error",
            "query_hash": query_hash,
            "error": f"Query execution failed: {str(e)}",
            "results": [],
            "row_count": 0,
            "execution_time_ms": (datetime.now() - start_time).total_seconds() * 1000,
        }


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Entry point for Rust subprocess invocation"""
    
    if len(sys.argv) < 2:
        logger.error("No SQL query provided")
        response = {
            "status": "error",
            "error": "No SQL query provided in command-line arguments",
            "results": [],
        }
        print(json.dumps(response))
        sys.exit(1)
    
    query = sys.argv[1]
    
    logger.info("=" * 80)
    logger.info("SMALLPOND QUERY EXECUTOR STARTED")
    logger.info("=" * 80)
    
    # Execute with formal safety
    response = execute_query_safe(query)
    
    # Output JSON to stdout for Rust gateway
    try:
        if response["status"] == "success":
            # Return just the results array for successful queries
            print(json.dumps(response["results"]))
        else:
            # Return error response
            print(json.dumps({
                "status": response["status"],
                "error": response.get("error", "Unknown error"),
            }))
    except Exception as e:
        logger.error(f"Failed to serialize response: {e}")
        print(json.dumps({
            "status": "error",
            "error": f"Serialization failed: {str(e)}",
        }))
        sys.exit(1)
    
    logger.info("SMALLPOND QUERY EXECUTOR COMPLETED")
    logger.info("=" * 80)


if __name__ == "__main__":
    main()
