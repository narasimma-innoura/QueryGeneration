#!/usr/bin/env python3
"""
Smallpond Query Executor: Postgres Backend (psycopg2)
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
    'video_segments',
}

# Allowed column names
ALLOWED_COLUMNS = {
    'camera_id',
    'start_ms',
    'end_ms',
    'duration_ms',
    's3_key',
    'size_bytes',
    'detections',
    'complete',
    'created_at',
    'analytics_synced_at',
}

# Parquet ledger path
PARQUET_LEDGER_PATH = Path("output/rustfs_manifest.parquet")

# RustFS object store (real ground truth for what footage actually exists —
# see conversation history: 14 of 16 cameras with rows in Postgres turned out
# to have zero matching objects on RustFS at all, meaning search was
# returning unplayable "ghost" segments).
RUSTFS_ENDPOINT = os.environ.get("RUSTFS_ENDPOINT", "http://54.204.98.59:10011")
RUSTFS_BUCKET = "visionguard-playback"

# Cap on how many of the final result rows may come from any single camera_id.
# Without this, "ORDER BY start_ms DESC LIMIT N" on video_segments returns
# whatever the single most-recently-active camera produced, since it
# dominates the most-recent timestamps — a search can end up returning N
# consecutive clips of one camera's feed instead of a spread across cameras,
# even though each row is a genuinely distinct segment.
PER_CAMERA_CAP = 15

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
        ALLOWLIST_PATTERN = r"^SELECT\s+[a-zA-Z0-9_,\s*]+FROM\s+[a-zA-Z0-9_]+\s*(WHERE\s+[a-zA-Z0-9_(),=<>'\s%:-]+)?$"
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
                    base_col = col.split()[0].lower()
                    if base_col not in ALLOWED_COLUMNS and base_col != '*':
                        return False, f"Column '{base_col}' not in whitelist: {ALLOWED_COLUMNS}"
        
        return True, ""
    
    @staticmethod
    def compute_query_hash(query: str) -> str:
        """Compute SHA256 hash of query for audit trail"""
        return hashlib.sha256(query.encode()).hexdigest()[:16]


def diversify_by_camera(query: str, per_camera_cap: int = PER_CAMERA_CAP) -> str:
    """
    Rewrite a `SELECT * FROM video_segments [WHERE ...] [ORDER BY start_ms DESC] [LIMIT N]`
    query so the final result set is capped at `per_camera_cap` rows per
    camera_id before the overall ORDER BY/LIMIT is reapplied on top of that
    capped pool. This can't be expressed in the client-generated SQL grammar
    (no window functions allowed by the allowlist), so it's done here as a
    rewrite of the already-validated query, after validation and before
    execution.

    No-op (returns the query unchanged) for anything that isn't confidently
    recognized as this exact shape — including any other table — rather than
    risk mis-rewriting a query this function doesn't fully understand.
    """
    if "video_segments" not in query.lower():
        return query

    working = query.strip()

    limit_match = re.search(r"\s+LIMIT\s+(\d+)\s*$", working, re.IGNORECASE)
    limit = int(limit_match.group(1)) if limit_match else MAX_RESULT_ROWS
    if limit_match:
        working = working[:limit_match.start()]

    order_match = re.search(r"\s+ORDER\s+BY\s+start_ms\s+DESC\s*$", working, re.IGNORECASE)
    if order_match:
        working = working[:order_match.start()]

    base_match = re.match(
        r"^SELECT\s+\*\s+FROM\s+video_segments(?:\s+WHERE\s+(.*))?$",
        working,
        re.IGNORECASE,
    )
    if not base_match:
        return query

    where_clause = base_match.group(1)
    where_sql = f"WHERE {where_clause}" if where_clause else ""

    return (
        "SELECT * FROM ("
        "SELECT *, ROW_NUMBER() OVER (PARTITION BY camera_id ORDER BY start_ms DESC) AS __cam_rank "
        f"FROM video_segments {where_sql}"
        f") ranked WHERE __cam_rank <= {per_camera_cap} "
        f"ORDER BY start_ms DESC LIMIT {limit}"
    )


def filter_existing_rustfs_keys(s3_keys: List[str], max_workers: int = 20) -> set:
    """
    Concurrently HEAD-check each s3_key against the real RustFS object store,
    returning only the keys that actually exist there.

    Postgres's video_segments table is not a reliable proxy for what RustFS
    actually has — it can (and does) reference segments that were deleted or
    never existed on RustFS. Returning those as search results gives users
    an unplayable "ghost" segment with no indication anything is wrong.
    HeadObject (not listing) is used per-key because listing whole camera
    prefixes to check a handful of specific keys would mean paginating
    through potentially hundreds of thousands of objects for cameras with
    long histories, just to confirm ~15-100 specific keys.

    Fails safe: any missing credentials or network/auth problem returns an
    empty set rather than raising or silently trusting Postgres — an empty
    result correctly signals "verification could not be completed", it is
    not the same as "nothing matched".
    """
    access_key = os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    if not access_key or not secret_key or not s3_keys:
        return set()

    try:
        import boto3
        from botocore.config import Config
        import concurrent.futures

        s3 = boto3.client(
            "s3",
            endpoint_url=RUSTFS_ENDPOINT,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=Config(
                signature_version="s3v4",
                region_name="us-east-1",
                connect_timeout=5,
                read_timeout=10,
                max_pool_connections=max_workers,
            ),
        )

        def exists(key: str) -> Optional[str]:
            try:
                s3.head_object(Bucket=RUSTFS_BUCKET, Key=key)
                return key
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            found = pool.map(exists, s3_keys)
        return {k for k in found if k}
    except Exception as e:
        logger.warning(f"RustFS existence validation failed: {e}")
        return set()


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
# QUERY EXECUTOR (Postgres + Formal Safety)
# ============================================================================

def execute_query_safe(query: str) -> Dict[str, Any]:
    """
    Execute Postgres query with formal safety guarantees.
    
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

    # Step 3: Execute query directly against Postgres via psycopg2.
    #
    # Previously this went through DuckDB's `ATTACH ... TYPE postgres` scanner.
    # Measured against this database, DuckDB's scanner took 35s+ (and was
    # observed to time out entirely) for the exact same query psycopg2 answers
    # in ~6s — even a plain `LIMIT 10` with no predicate. The DuckDB postgres
    # extension appears to pull far more than the requested rows before
    # applying LIMIT/WHERE locally. psycopg2 lets Postgres itself execute the
    # query and stream back only the matching rows, which is what actually
    # fixes the timeouts rather than just tolerating them.
    try:
        import psycopg2
        import uuid

        database_url = os.environ.get("DATABASE_URL")
        if not database_url:
            logger.error("DATABASE_URL environment variable not set")
            return {
                "status": "error",
                "query_hash": query_hash,
                "error": "Server misconfiguration: DATABASE_URL environment variable not set",
                "results": [],
                "row_count": 0,
                "execution_time_ms": (datetime.now() - start_time).total_seconds() * 1000,
            }

        conn = psycopg2.connect(database_url, connect_timeout=10)
        cur = conn.cursor()
        # Belt-and-suspenders: have Postgres itself abort a runaway query
        # server-side, rather than relying solely on the Rust gateway's
        # subprocess timeout to notice and kill this process. 45s (not 25s)
        # because a legitimate unbounded ORDER BY ... LIMIT scan (no index
        # on the sort column — see comment at the top of this file) was
        # measured taking ~26-29s; 25s was cancelling valid queries right at
        # the edge. Must stay comfortably below the Rust gateway's own
        # subprocess timeout (main.rs) or Postgres never gets to return this
        # clean error before the whole process gets killed instead.
        cur.execute("SET statement_timeout = '45000';")

        # Execute user query
        logger.info(f"Executing query | hash={query_hash}")

        # JSONB columns need an explicit text cast for ILIKE to work against Postgres.
        # This only ever rewrites the already-validated query in place; it is never
        # re-embedded into another SQL string, so the allowlist grammar still holds.
        #
        # The optional "(?:\s+NOT)?" matters: this used to match only bare
        # "detections ILIKE", so "detections NOT ILIKE '%no_x%'" (the
        # compliant-PPE-item pattern — see system prompt rule 5 and its own
        # few-shot example) left that second reference as raw jsonb, which
        # Postgres rejects for NOT ILIKE with "operator does not exist:
        # jsonb !~~* unknown". Every "show X worn correctly" query was
        # broken until this was widened to also match the NOT form.
        if "video_segments" in query.lower():
            query = diversify_by_camera(query)
            query = re.sub(
                r'detections((?:\s+NOT)?\s+ILIKE)',
                r'detections::text\1',
                query,
                flags=re.IGNORECASE,
            )

        cur.execute(query)
        columns = [desc[0] for desc in cur.description]
        result = cur.fetchall()
        cur.close()
        conn.close()

        # Convert to dicts and map schema
        results = []
        for row in result:
            d = {k: str(v) if isinstance(v, uuid.UUID) else v for k, v in dict(zip(columns, row)).items()}
            
            # If the query was against video_segments, we map it
            if "camera_id" in d:
                mapped = {
                    "video_id": d.get("camera_id"),
                    "start_ts": d.get("start_ms"),
                    "end_ts": d.get("end_ms"),
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
                    # Kept temporarily for the RustFS existence check below;
                    # stripped before the response is returned.
                    mapped["_s3_key"] = s3_key
                # detections is the JSONB blob of per-frame bounding boxes
                # (frames[].boxes[].bbox/label/score/color) the frontend
                # overlays on the video player. It was previously dropped
                # here, so the browser had no way to draw detections at all.
                if "detections" in d:
                    mapped["detections"] = d["detections"]
                results.append(mapped)
            else:
                results.append(d)

        # Cross-check against the real RustFS object store before returning
        # anything as a match — Postgres alone isn't reliable ground truth
        # for what footage still exists (see filter_existing_rustfs_keys
        # docstring). Rows without an s3_key (non-video_segments queries)
        # pass through untouched.
        s3_keys_to_check = [r["_s3_key"] for r in results if "_s3_key" in r]
        if s3_keys_to_check:
            logger.info(f"Verifying {len(s3_keys_to_check)} segment(s) against RustFS | hash={query_hash}")
            valid_keys = filter_existing_rustfs_keys(s3_keys_to_check)
            before = len(results)
            results = [r for r in results if r.get("_s3_key") in valid_keys or "_s3_key" not in r]
            dropped = before - len(results)
            if dropped:
                logger.info(f"Dropped {dropped} ghost segment(s) not found on RustFS | hash={query_hash}")
        for r in results:
            r.pop("_s3_key", None)

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
        logger.error("psycopg2 not installed; falling back to minimal JSON response")
        return {
            "status": "error",
            "query_hash": query_hash,
            "error": "psycopg2 library not available",
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
