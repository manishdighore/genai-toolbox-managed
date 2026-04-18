#!/usr/bin/env bash
# build-run.sh — Build and run dbmcp in detached mode (SQLite, local tier)
set -euo pipefail

CONTAINER_NAME="dbmcp"
IMAGE_NAME="dbmcp:latest"
DATA_DIR="$(pwd)/dbmcp-data"
PORT=5001

# ── Colours ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[dbmcp]${NC} $*"; }
success() { echo -e "${GREEN}[dbmcp]${NC} $*"; }
warn()    { echo -e "${YELLOW}[dbmcp]${NC} $*"; }

# ── 1. Build image ────────────────────────────────────────────────────────────
info "Building Docker image ${IMAGE_NAME} ..."
docker build \
  -f fork/Dockerfile.dbmcp \
  -t "${IMAGE_NAME}" \
  fork/

success "Image built: ${IMAGE_NAME}"

# ── 2. Ensure data directory exists ───────────────────────────────────────────
mkdir -p "${DATA_DIR}"
info "Data directory: ${DATA_DIR}"

# ── 3. Stop + remove any existing container ───────────────────────────────────
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
  warn "Removing existing container '${CONTAINER_NAME}' ..."
  docker rm -f "${CONTAINER_NAME}" >/dev/null
fi

# ── 4. Encryption key ─────────────────────────────────────────────────────────
KEY_FILE="${DATA_DIR}/.encryption_key"
if [ -f "${KEY_FILE}" ]; then
  ENCRYPTION_KEY="$(cat "${KEY_FILE}")"
  info "Using existing encryption key from ${KEY_FILE}"
else
  ENCRYPTION_KEY="$(openssl rand -hex 32)"
  echo "${ENCRYPTION_KEY}" > "${KEY_FILE}"
  chmod 600 "${KEY_FILE}"
  success "Generated new encryption key → ${KEY_FILE}"
fi

# ── 5. Run detached, auto-restart ─────────────────────────────────────────────
info "Starting container '${CONTAINER_NAME}' on port ${PORT} ..."
docker run -d \
  --name "${CONTAINER_NAME}" \
  --restart unless-stopped \
  -p "${PORT}:5001" \
  -v "${DATA_DIR}:/data" \
  -e DBMCP_ENCRYPTION_KEY="${ENCRYPTION_KEY}" \
  "${IMAGE_NAME}"

# ── 6. Health check ───────────────────────────────────────────────────────────
info "Waiting for server to be ready ..."
for i in $(seq 1 20); do
  if curl -sf "http://127.0.0.1:${PORT}/api/connections" >/dev/null 2>&1; then
    success "Server is up at http://localhost:${PORT}"
    break
  fi
  sleep 1
  if [ "$i" -eq 20 ]; then
    warn "Server did not respond in 20s — check logs:"
    docker logs --tail 30 "${CONTAINER_NAME}"
    exit 1
  fi
done

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  API:      http://localhost:${PORT}/api/connections"
echo -e "  Docs UI:  http://localhost:${PORT}/docs"
echo -e "  OpenAPI:  http://localhost:${PORT}/openapi.yaml"
echo -e "  Data dir: ${DATA_DIR}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  docker logs -f ${CONTAINER_NAME}   # follow logs"
echo "  docker stop ${CONTAINER_NAME}      # stop"
echo "  docker rm   ${CONTAINER_NAME}      # remove"
