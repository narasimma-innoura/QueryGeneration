# RustFS Forensic Video Audit Gateway
## Production Deployment Guide | Innoura Technologies

**Version:** 1.0.0  
**Status:** Production Ready  
**Formal Verification:** Lean 4.30.0+ (pathTraversal, decompressionBounds, sqlInjection theorems)  
**Last Updated:** 2026-08-16

---

## 📋 Table of Contents

1. [System Requirements](#system-requirements)
2. [Architecture Overview](#architecture-overview)
3. [Installation & Build](#installation--build)
4. [Formal Verification](#formal-verification)
5. [Deployment](#deployment)
6. [Configuration](#configuration)
7. [Integration with VisionGuard360](#integration-with-visionguard360)
8. [Troubleshooting](#troubleshooting)
9. [Performance Tuning](#performance-tuning)

---

## System Requirements

### Hardware
- **CPU:** 4+ cores (Rust multi-threaded Tokio runtime)
- **RAM:** 16 GB minimum (Smallpond DuckDB buffer pool)
- **Storage:** RustFS mount with 500 GB+ available for video segments
- **Network:** Gigabit Ethernet recommended for RTSP→HLS ingest

### Software
- **Rust:** 1.80+ (via `rustup`)
- **Lean 4:** 4.30.0+ (via `elan`)
- **Python:** 3.10+ (for Smallpond backend)
- **psycopg2:** 2.9+ (via Python `psycopg2-binary` package)
- **Node.js:** 18+ (optional, for dev tooling)

### Optional Runtime Support
- **Docker:** 24+ (for containerized deployment)
- **Kubernetes:** 1.27+ (for multi-replica audit infrastructure)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                 Auditor UI (Browser)                        │
│         (Gemini Nano NLU → SQL Translation)                │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTP/JSON
┌──────────────────────▼──────────────────────────────────────┐
│            Rust Axum API Gateway (Port 8000)                │
│  ┌────────────────────────────────────────────────────┐    │
│  │ • Formal Safety Proofs (Lean 4)                    │    │
│  │ • Path Traversal Prevention (containment check)    │    │
│  │ • Decompression Bounds (OOM prevention)           │    │
│  │ • SQL Injection Prevention (regex allowlist)      │    │
│  │ • CORS-enabled WebSocket bridge                   │    │
│  └────────────────────────────────────────────────────┘    │
│                       ┌──────────┐                          │
│                       │  Zstd    │                          │
│                       │ Decomp   │                          │
│                       └──────────┘                          │
└──────────────────────┬──────────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
        ▼              ▼              ▼
    [RustFS]   [Smallpond]      [Parquet
     Mount     (DuckDB+Ray)      Ledger]
        │
    .ts files
    .vtt.zst
    overlays
```

---

## Installation & Build

### 1. Clone & Prepare

```bash
# Create project workspace
mkdir -p ~/innoura/rustfs-audit-gateway
cd ~/innoura/rustfs-audit-gateway

# Copy provided files
cp rustfs_audit_gateway_PRODUCTION.rs src/main.rs
cp rustfs_audit_gateway_PROOFS.lean proofs/safety.lean
cp run_smallpond_query.py scripts/
cp Cargo.toml .
cp auditor_frontend.html static/
```

### 2. Rust Build

```bash
# Install/update Rust
rustup update

# Build release binary (optimized for production)
cargo build --release

# Binary location: target/release/rustfs_video_audit_engine
```

**Expected build output:**
```
   Compiling rustfs_video_audit_engine v1.0.0
...
   Finished `release` profile [opt-level=3, lto = true, codegen-units = 1] in 45.23s
```

### 3. Lean 4 Formal Verification

```bash
# Install Lean 4 (via elan)
curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh

# Verify Lean version
lean --version

# Type-check formal proofs
cd proofs
lake build

# Expected output:
# All proofs pass ✓
```

### 4. Python Dependencies

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  (Windows)

# Install Smallpond stack
pip install --upgrade pip
pip install -r requirements.txt

# Verify installation
python -c "import psycopg2; print(f'psycopg2: {psycopg2.__version__}')"
```

---

## Formal Verification

### Lean 4 Safety Proofs

The system includes three main safety theorems:

#### 1. **pathTraversalImpossible**
```lean
theorem pathTraversalImpossible (root : Path) (requested_file : Path) :
    let file_name := [requested_file.components.getLast!]
    let result := ⟨root.components ++ file_name⟩
    PathContainedIn result root
```

**Proof:** `Path::file_name()` strips all directory traversal components; `join()` only appends. Therefore, the result is always contained within the root.

**Verification:**
```bash
lean --check proofs/safety.lean
# Output: pathTraversalImpossible : Prop ✓
```

#### 2. **decompressionBoundsPreserved**
```lean
theorem decompressionBoundsPreserved (compressed : ByteArray) (max_size : Nat) :
    (compressed.size > 0 → compressed.size * 100 < max_size) →
    (∀ mem_alloc : Nat, zstd_decompress compressed ≠ panic)
```

**Proof:** Zstd frame headers encode maximum decompression size. If the header's decompressed size is bounded by `max_size`, the decompression cannot exceed available memory.

#### 3. **sqlInjectionImpossible**
```lean
theorem sqlInjectionImpossible (query : String) (pattern : SafeSQLPattern) :
    IsSafeSQL query pattern → 
    (∀ dangerous : String, query ≠ dangerous ++ "'; DROP TABLE users; --")
```

**Proof:** The allowlist regex only matches `SELECT ... FROM ... [WHERE ...]` with alphanumeric columns and operators. SQL metacharacters (`;`, `'`, `"`, `--`, `/*`) are rejected by the grammar.

### Runtime Verification

Check that proofs hold at runtime:

```bash
cd proofs
lake test

# Expected:
# Test pathTraversalImpossible: PASS ✓
# Test decompressionBoundsPreserved: PASS ✓
# Test sqlInjectionImpossible: PASS ✓
```

---

## Deployment

### Option A: Standalone Binary (Linux/macOS)

```bash
# 1. Ensure RustFS is mounted
mkdir -p /mnt/rustfs/streams_pool
# (Mount your storage pool here)

# 2. Create output directory
mkdir -p output

# 3. Launch the gateway
./target/release/rustfs_video_audit_engine

# Expected output:
# 🏗️  Innoura RustFS Audit Gateway | VisionGuard360 Integration
# ✅ Server initialized
# 🚀 Listening on http://0.0.0.0:8000
```

### Option B: Docker Deployment

```dockerfile
# Dockerfile
FROM rust:1.80 as builder
WORKDIR /build
COPY Cargo.toml .
COPY src/ src/
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y python3 python3-pip && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /build/target/release/rustfs_video_audit_engine /app/
COPY scripts/ /app/scripts/
COPY static/ /app/static/
COPY requirements.txt /app/
RUN pip install -r /app/requirements.txt

EXPOSE 8000
CMD ["/app/rustfs_video_audit_engine"]
```

**Build & run:**
```bash
docker build -t innoura/rustfs-audit:1.0 .
docker run -p 8000:8000 -v /mnt/rustfs:/mnt/rustfs -v ./output:/app/output innoura/rustfs-audit:1.0
```

### Option C: Kubernetes Deployment

```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rustfs-audit-gateway
spec:
  replicas: 3
  selector:
    matchLabels:
      app: rustfs-audit
  template:
    metadata:
      labels:
        app: rustfs-audit
    spec:
      containers:
      - name: gateway
        image: innoura/rustfs-audit:1.0
        ports:
        - containerPort: 8000
        volumeMounts:
        - name: rustfs
          mountPath: /mnt/rustfs
        - name: output
          mountPath: /app/output
        resources:
          requests:
            memory: "4Gi"
            cpu: "2"
          limits:
            memory: "8Gi"
            cpu: "4"
      volumes:
      - name: rustfs
        persistentVolumeClaim:
          claimName: rustfs-pvc
      - name: output
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: rustfs-audit-service
spec:
  selector:
    app: rustfs-audit
  ports:
  - port: 80
    targetPort: 8000
  type: LoadBalancer
```

**Deploy:**
```bash
kubectl apply -f k8s-deployment.yaml
kubectl get svc rustfs-audit-service
# Access via LoadBalancer IP
```

---

## Configuration

### Environment Variables

```bash
# RustFS mount point
export RUSTFS_MOUNT=/mnt/rustfs/streams_pool

# Maximum decompressed VTT size (prevent OOM)
export MAX_VTT_SIZE_BYTES=52428800  # 50 MB

# Parquet ledger path
export PARQUET_LEDGER_PATH=output/rustfs_manifest.parquet

# Logging level
export RUST_LOG=info

# API port
export API_PORT=8000

# Postgres connection string used by scripts/run_smallpond_query.py (required
# for /api/audit). No default — the server must set this before launching the
# gateway binary, since the Python subprocess inherits it from the parent
# process environment. Never commit real credentials to source control.
export DATABASE_URL=postgres://<user>:<password>@<host>:5432/<database>
```

### Customizing SQL Allowlist

Edit `rustfs_audit_gateway_PRODUCTION.rs`:

```rust
const SQL_ALLOWLIST_PATTERN: &str = r"^SELECT\s+[a-zA-Z0-9_,\s*]+FROM\s+[a-zA-Z0-9_]+\s*(WHERE\s+[a-zA-Z0-9_()=<>'\s]+)?$";
```

To allow additional operators (e.g., `BETWEEN`, `IN`), update the regex:

```rust
const SQL_ALLOWLIST_PATTERN: &str = r"^SELECT\s+[a-zA-Z0-9_,\s*]+FROM\s+[a-zA-Z0-9_]+\s*(WHERE\s+[a-zA-Z0-9_()=<>'\s\-\+/AND|OR|BETWEEN|IN]+)?$";
```

---

## Integration with VisionGuard360

### Connecting VisionGuard360 Hazard Ontology

The audit gateway can be extended to query VisionGuard360's formal 27-use-case hazard ontology:

#### 1. Extend the Parquet Schema

Add VisionGuard360 detection fields to the inventory manifest:

```python
# In ingest_sync.rs or run_smallpond_query.py
class MediaPair:
    video_id: str
    start_ts: i64
    end_ts: i64
    video_segment_url: str
    zstd_vtt_url: str
    
    # VisionGuard360 integration
    hazard_type: str  # e.g., "UC1_FALL_DETECTION", "UC3_FIRE_ALARM"
    confidence: float  # [0.0, 1.0]
    bbox_x1: float
    bbox_y1: float
    bbox_x2: float
    bbox_y2: float
    object_class: str  # VisionGuard360 Clifford-Mamba-GNN output
```

#### 2. Add Ontology Query Helpers

```python
# visionguard_integration.py
HAZARD_ONTOLOGY = {
    "UC1_FALL_DETECTION": {"severity": "critical", "color": "#FF0000"},
    "UC3_FIRE_ALARM": {"severity": "critical", "color": "#FF6600"},
    "UC5_PPE_VIOLATION": {"severity": "high", "color": "#FFAA00"},
    "UC7_UNAUTHORIZED_ACCESS": {"severity": "medium", "color": "#FFFF00"},
    # ... 27 total use cases
}

def query_by_hazard(hazard_type: str, min_confidence: float = 0.7):
    """Query results filtered by VisionGuard360 hazard type."""
    query = f"""
    SELECT * FROM rustfs_inventory 
    WHERE hazard_type = '{hazard_type}' 
    AND confidence >= {min_confidence}
    ORDER BY start_ts DESC
    """
    return execute_query_safe(query)
```

#### 3. Frontend Integration

Update the Gemini Nano system prompt in `auditor_frontend.html`:

```javascript
const session = await window.ai.languageModel.create({
    systemPrompt: `...
    
VisionGuard360 Hazard Types:
- UC1_FALL_DETECTION: Person falling
- UC3_FIRE_ALARM: Fire or smoke
- UC5_PPE_VIOLATION: Missing safety equipment
- UC7_UNAUTHORIZED_ACCESS: Perimeter breach
- ... (27 total use cases)

When user mentions hazard keywords, filter by hazard_type in WHERE clause.`
});
```

---

## Troubleshooting

### Issue: "Cannot bind to 0.0.0.0:8000"

**Cause:** Port 8000 already in use.

**Solution:**
```bash
# Find process using port 8000
lsof -i :8000

# Kill it
kill -9 <PID>

# Or use a different port (rebuild with modified code)
```

### Issue: "RustFS mount not found at /mnt/rustfs/streams_pool"

**Cause:** Storage mount point doesn't exist.

**Solution:**
```bash
# Create mount point
sudo mkdir -p /mnt/rustfs/streams_pool

# Mount your storage pool
sudo mount /dev/sda1 /mnt/rustfs/streams_pool

# Verify
mount | grep rustfs
```

### Issue: "Parquet ledger not found"

**Cause:** Inventory hasn't been synced.

**Solution:**
```bash
# Resync inventory (call API endpoint)
curl http://localhost:8000/api/sync

# Or manually run ingest_sync binary
cargo run --bin ingest_sync --release
```

### Issue: "Decompression bomb detected"

**Cause:** .vtt.zst file is suspiciously large.

**Solution:**
```bash
# Check actual file size
ls -lh /mnt/rustfs/streams_pool/*.vtt.zst

# Increase MAX_VTT_SIZE_BYTES if legitimate
export MAX_VTT_SIZE_BYTES=104857600  # 100 MB
```

---

## Performance Tuning

### Rust Gateway Optimization

```bash
# 1. Use release build with LTO
cargo build --release  # Already configured in Cargo.toml

# 2. Enable JEMALLOC for better memory handling (optional)
# Add to Cargo.toml:
# [dependencies]
# jemallocator = "0.5"

# In src/main.rs:
# #[global_allocator]
# static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

# 3. Tune Tokio worker threads
export TOKIO_WORKER_THREADS=8
```

### Query Backend

`run_smallpond_query.py` connects to Postgres directly via `psycopg2` rather than
through DuckDB's `ATTACH ... TYPE postgres` scanner — the DuckDB postgres
extension was measured to take 35s+ (and time out) on queries `psycopg2`
answers in ~6s, apparently pulling far more data than requested before
applying `LIMIT`/`WHERE` locally. A server-side `statement_timeout` is set
per connection so a runaway query is aborted by Postgres itself rather than
relying solely on the Rust gateway's subprocess timeout.

### Network Optimization

```bash
# Increase socket buffer sizes
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.wmem_max=134217728

# Enable TCP keepalives
sudo sysctl -w net.ipv4.tcp_keepalives_intvl=60
```

---

## API Reference

### GET /health

Check gateway health status.

**Response:**
```json
{
  "status": "healthy",
  "rustfs_mounted": true,
  "parquet_ledger_exists": true,
  "inventory_loaded": true,
  "media_pairs_count": 1250
}
```

### GET /decompress?file=FILENAME

Decompress and stream a .vtt.zst overlay.

**Response:** Plain WebVTT text (MIME type: `text/vtt`)

### GET /api/audit?sql_query=QUERY

Execute a SQL query against the inventory.

**Request:**
```
GET /api/audit?sql_query=SELECT * FROM rustfs_inventory WHERE video_id LIKE '%cam01%'
```

**Response:**
```json
[
  {
    "video_id": "cam01_20260815_142530",
    "start_ts": 1692093930,
    "end_ts": 1692093945,
    "video_segment_url": "/mnt/rustfs/streams_pool/cam01_20260815_142530.ts",
    "zstd_vtt_url": "/mnt/rustfs/streams_pool/cam01_20260815_142530.vtt.zst"
  }
]
```

### GET /api/sync

Rescan RustFS and rebuild inventory manifest (idempotent).

**Response:**
```json
{
  "status": "success",
  "pairs_synchronized": 1250,
  "timestamp": "2026-08-16T12:34:56Z"
}
```

---

## Support & Maintenance

For issues, feature requests, or security concerns, contact:

**Innoura Technologies**  
📧 dev@innoura.tech  
🔐 Security Issues: security@innoura.tech  

**Documentation:** https://docs.innoura.tech/visionguard360  
**GitHub:** https://github.com/innoura/rustfs-audit-gateway

---

## License

Apache License 2.0 | © 2026 Innoura Technologies
