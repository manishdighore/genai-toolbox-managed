#!/usr/bin/env bash
# build-run.sh — Build and run dbmcp in detached mode against a Postgres DB.
#
# Reads configuration from `.env` (gitignored) if present:
#   DBMCP_APP_KEY  (required)       — 32-byte hex master key
#   PG_HOST / PG_PORT / PG_USER / PG_PASS / PG_DB / PG_SSLMODE  (optional)
#
# First-time setup:
#   cp .env.example .env
#   echo "DBMCP_APP_KEY=$(openssl rand -hex 32)" >> .env   # or edit by hand
#   ./build-run.sh
set -euo pipefail

# ── 0. Load .env if present ──────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
if [ -f "${ENV_FILE}" ]; then
  set -a; . "${ENV_FILE}"; set +a
fi

CONTAINER_NAME="dbmcp"
IMAGE_NAME="dbmcp:latest"
PORT=5001

# Postgres target — defaults match the AgentForge dev compose.
PG_HOST="${PG_HOST:-host.docker.internal}"
PG_PORT="${PG_PORT:-5432}"
PG_USER="${PG_USER:-agentforge}"
PG_PASS="${PG_PASS:-agentforge}"
PG_DB="${PG_DB:-agentforge}"
PG_SSLMODE="${PG_SSLMODE:-disable}"

# Master key for envelope encryption of rows in the shared `credentials` table.
if [ -z "${DBMCP_APP_KEY:-}" ]; then
  echo "ERROR: DBMCP_APP_KEY is required." >&2
  echo "Generate one and add it to .env:" >&2
  echo "  echo \"DBMCP_APP_KEY=\$(openssl rand -hex 32)\" >> .env" >&2
  exit 1
fi

# ── Colours ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[dbmcp]${NC} $*"; }
success() { echo -e "${GREEN}[dbmcp]${NC} $*"; }
warn()    { echo -e "${YELLOW}[dbmcp]${NC} $*"; }

# ── 1. Build image ────────────────────────────────────────────────────────────
info "Building Docker image ${IMAGE_NAME} ..."
docker build \
  -f Dockerfile.dbmcp \
  -t "${IMAGE_NAME}" \
  .
success "Image built: ${IMAGE_NAME}"

# ── 2. Stop + remove any existing container ───────────────────────────────────
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
  warn "Removing existing container '${CONTAINER_NAME}' ..."
  docker rm -f "${CONTAINER_NAME}" >/dev/null
fi

# ── 3. Build the Postgres DSN ────────────────────────────────────────────────
DB_URL="postgres://${PG_USER}:${PG_PASS}@${PG_HOST}:${PG_PORT}/${PG_DB}?sslmode=${PG_SSLMODE}"
info "Postgres target: ${PG_HOST}:${PG_PORT}/${PG_DB} (user=${PG_USER}, sslmode=${PG_SSLMODE})"

# ── 4. Run detached, auto-restart ─────────────────────────────────────────────
info "Starting container '${CONTAINER_NAME}' on port ${PORT} ..."
docker run -d \
  --name "${CONTAINER_NAME}" \
  --restart unless-stopped \
  -p "${PORT}:5001" \
  -e DBMCP_APP_KEY="${DBMCP_APP_KEY}" \
  "${IMAGE_NAME}" \
  --config-mode=db \
  --security-tier=local \
  --port=5001 \
  --db-url="${DB_URL}" \
  --secrets-backend=credentials \
  --app-key="${DBMCP_APP_KEY}"

# ── 5. Health check ───────────────────────────────────────────────────────────
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
echo -e "  Postgres: ${PG_HOST}:${PG_PORT}/${PG_DB}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  docker logs -f ${CONTAINER_NAME}   # follow logs"
echo "  docker stop ${CONTAINER_NAME}      # stop"
echo "  docker rm   ${CONTAINER_NAME}      # remove"
