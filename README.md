# genai-toolbox-managed

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26+-00ADD8?logo=go)](https://go.dev)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker)](fork/Dockerfile.dbmcp)
[![Based on genai-toolbox](https://img.shields.io/badge/based%20on-genai--toolbox-4285F4?logo=google)](https://github.com/googleapis/genai-toolbox)
[![MCP](https://img.shields.io/badge/protocol-MCP-8B5CF6)](https://modelcontextprotocol.io)

**One interface. Every database. Instant MCP.**

Connect any database to any AI agent — without editing config files, without restarting servers, without writing code. Register a connection once and it's live as an MCP endpoint immediately.

Built on [googleapis/genai-toolbox](https://github.com/googleapis/genai-toolbox).

---

## What becomes possible

**Your agent can query any of your databases — just by knowing their name.**

```
Claude / Cursor / Copilot
         │
         ▼
  genai-toolbox-managed
  ┌──────────────────────────────────┐
  │  /mcp/prod-postgres   (21 tools) │
  │  /mcp/analytics-mysql  (6 tools) │
  │  /mcp/mongo-logs       (1 tool)  │
  │  /mcp/redis-cache      (4 tools) │
  └──────────────────────────────────┘
         │
         ▼
  Your databases — anywhere
```

Add a database through the UI or API. It's live in seconds. Remove it — it's gone. No YAML. No restarts.

---

## What your agent can do

Once a database is connected, your agent gets the full toolkit for that database — not just "run a query":

**PostgreSQL** — list tables, schemas, views, indexes, roles, active queries, locks, slow queries, table stats, extensions, and more. 21 tools total.

**MySQL / MariaDB** — execute queries, list tables, inspect query plans, find missing indexes, view fragmentation. 6 tools.

**SQL Server** — execute queries, list tables.

**MongoDB, Redis, Neo4j, Cassandra, Elasticsearch, Snowflake, ClickHouse** — native tools for each.

→ Full list: [Supported Databases](fork/docs/dbmcp/DATABASES.md)

---

## How it works

**Register a connection:**
```bash
# Works from any UI, curl, or SDK
POST /api/connections
{
  "name": "prod-postgres",
  "db_type": "postgres",
  "host": "db.example.com",
  "port": 5432,
  "database": "myapp",
  "username": "readonly",
  "password": "..."
}
```

**Point your agent at it:**
```json
{
  "mcpServers": {
    "prod-postgres": {
      "type": "http",
      "url": "http://localhost:5001/mcp/prod-postgres"
    }
  }
}
```

That's it. Your agent now has 21 Postgres tools available — tables, schemas, slow queries, indexes, everything.

Or point at `/mcp` to get all databases in one endpoint.

---

## Credentials stay secret

Passwords are never stored in plaintext — not in the database, not in logs, not in responses. They go straight into an encrypted secrets store.

Choose where secrets live based on where you deploy:

| Where you run | Secrets backend |
|---------------|----------------|
| Local / self-hosted | Encrypted SQLite file |
| Google Cloud | GCP Secret Manager |
| AWS | AWS Secrets Manager |
| Azure | Azure Key Vault |

→ Details: [Security](fork/docs/dbmcp/SECURITY.md)

---

## Three ways to use credentials

| Mode | How it works |
|------|-------------|
| **Local** | Password staged for 5 minutes, then encrypted at rest |
| **Enterprise** | Password encrypted on the client before it ever leaves your machine |
| **SaaS** | Password written directly to your secrets manager — server never sees it |

→ Details: [API Reference](fork/docs/dbmcp/API.md#security-tiers)

---

## Get started

**Docker (fastest):**
```bash
git clone https://github.com/yourname/genai-toolbox-managed
cd genai-toolbox-managed
bash build-run.sh
```

Opens at `http://localhost:5001` — API docs at `http://localhost:5001/docs`.

→ Full setup: [Running](fork/docs/dbmcp/RUNNING.md)

---

## Explore the API

An interactive API explorer is served at runtime — no Postman, no external tools needed.

```
http://localhost:5001/docs
```

→ Markdown reference: [API Reference](fork/docs/dbmcp/API.md)

---

## Based on genai-toolbox

This is a managed distribution of **[googleapis/genai-toolbox](https://github.com/googleapis/genai-toolbox)** — Google's MCP Toolbox for Databases. All 40+ database drivers, the MCP protocol implementation, connection pooling, and OpenTelemetry instrumentation come from upstream unchanged.

What we add: a REST API, database-backed connection management, encrypted secrets storage, and automatic MCP endpoint registration — so you don't need to touch a config file to connect a database to your agent.

Upstream license: Apache 2.0 · This fork: Apache 2.0
