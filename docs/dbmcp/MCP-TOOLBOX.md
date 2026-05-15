# MCP Toolbox for Databases — Architecture & Integration Guide

> **Source:** [googleapis/genai-toolbox](https://github.com/googleapis/genai-toolbox)  
> **Docs:** [mcp-toolbox.dev](https://mcp-toolbox.dev)  
> **Latest release:** v0.31.0  
> **License:** Apache 2.0

---

## Table of Contents

1. [What Is MCP Toolbox?](#1-what-is-mcp-toolbox)
2. [How It Works — Core Architecture](#2-how-it-works--core-architecture)
3. [One Server or Multiple Servers?](#3-one-server-or-multiple-servers)
4. [Key Concepts](#4-key-concepts)
   - [Sources](#41-sources)
   - [Tools](#42-tools)
   - [Toolsets](#43-toolsets)
   - [AuthServices](#44-authservices)
   - [Prompts](#45-prompts)
5. [Configuration: tools.yaml](#5-configuration-toolsyaml)
6. [Connecting Agents to Toolbox](#6-connecting-agents-to-toolbox)
7. [Supported Databases (Sources)](#7-supported-databases-sources)
8. [Security Model](#8-security-model)
9. [Integration Strategy for AgentForge](#9-integration-strategy-for-agentforge)
10. [Multi-User / Multi-Tenant Architecture](#10-multi-user--multi-tenant-architecture)
11. [Dynamic Config Generation Pattern](#11-dynamic-config-generation-pattern)
12. [Example: User Configures a DB Connection](#12-example-user-configures-a-db-connection)
13. [What AgentForge Needs to Build](#13-what-agentforge-needs-to-build)

---

## 1. What Is MCP Toolbox?

**MCP Toolbox for Databases** is an open-source [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) **server written in Go** that acts as a bridge between AI agents and databases. It serves a **dual purpose**:

| Mode | Use Case |
|------|----------|
| **Ready-to-use MCP Server** | Instantly connect AI IDEs/CLIs (Claude Code, Gemini CLI, Codex) to databases using prebuilt generic tools like `list_tables`, `execute_sql` |
| **Custom Tools Framework** | Build production-safe tools with predefined queries, structured parameters, and per-user authentication |

**Key benefits over raw database connections:**

- **Connection pooling** — manages database connection pools efficiently
- **Integrated auth (IAM / OIDC)** — tools can require and auto-populate user identity
- **End-to-end observability** — built-in OpenTelemetry traces and metrics
- **Safety** — tools use prepared statements, not raw SQL injection from LLMs
- **SDK support** — Python, JS/TS, Go, Java SDKs for easy agent integration

---

## 2. How It Works — Core Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      AI Agent / LLM                      │
│    (ADK, LangChain, LlamaIndex, CopilotKit, etc.)       │
└───────────────────────┬─────────────────────────────────┘
                        │  MCP Protocol (HTTP/SSE or stdio)
                        │  OR Toolbox SDK (Python/JS/Go)
                        ▼
┌─────────────────────────────────────────────────────────┐
│              MCP Toolbox Server (Go binary)              │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │  Source  │  │  Tools   │  │ Toolsets │              │
│  │ (DB conn)│  │(SQL stmts│  │(grouped  │              │
│  │  pools   │  │  + auth) │  │  tools)  │              │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘              │
│       └─────────────┴─────────────┘                     │
│                  tools.yaml config                       │
└──────────────────────┬──────────────────────────────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
     PostgreSQL     MongoDB       MySQL
     (Source 1)   (Source 2)   (Source 3)
```

**Request flow for a tool call:**
1. Agent calls a tool (e.g., `search_customers`) via MCP or SDK
2. Toolbox validates auth token (if `authRequired` is set)
3. Toolbox extracts authenticated params from OIDC token (e.g., `user_id`)
4. Toolbox executes the **pre-defined prepared statement** against the correct source
5. Result is returned to the agent

---

## 3. One Server or Multiple Servers?

### **Answer for AgentForge: ONE server, multiple sources**

A single Toolbox server instance can manage **multiple database sources simultaneously**. You do NOT need separate servers per database or per user.

```yaml
# tools.yaml — ONE server, THREE sources

kind: sources
name: user-postgres-db
type: postgres
host: ${USER_PG_HOST}
port: 5432
database: ${USER_PG_DB}
user: ${USER_PG_USER}
password: ${USER_PG_PASSWORD}
---
kind: sources
name: user-mysql-db
type: mysql
host: ${USER_MYSQL_HOST}
port: 3306
database: ${USER_MYSQL_DB}
user: ${USER_MYSQL_USER}
password: ${USER_MYSQL_PASSWORD}
---
kind: sources
name: company-bigquery
type: bigquery
project: ${GCP_PROJECT}
dataset: analytics
```

### When you WOULD use multiple servers:
- **Hard isolation requirements** (e.g., different security zones, VPCs)
- **Different geographic deployments** (source near data)
- **Extreme scale** — millions of tools across hundreds of databases
- **Separate Toolbox versions** per environment (dev/staging/prod)

### For a SaaS platform like AgentForge:
- **Dev/test:** One server, multiple sources in `tools.yaml`
- **Production:** Consider one Toolbox server per user tenant OR a shared server with per-user toolsets and auth

---

## 4. Key Concepts

### 4.1 Sources

A **Source** is a configured connection to a database. Each source = one connection pool to one database.

```yaml
kind: sources
name: my-pg-source          # referenced by tools
type: postgres              # database driver type
host: 127.0.0.1
port: 5432
database: toolbox_db
user: ${USER_NAME}          # use env vars, not hardcoded secrets!
password: ${PASSWORD}
```

- Multiple sources of different types can coexist in one `tools.yaml`
- Sources are named and referenced by tools
- Each source is an independent connection pool

### 4.2 Tools

A **Tool** is an action the agent can take — typically a SQL statement or database operation.

```yaml
kind: tools
name: search_customers_by_email
type: postgres-sql
source: my-pg-source          # which source to run against
description: |
  Search for a customer by their email address.
  Returns customer id, name, and account info.
parameters:
  - name: email
    type: string
    description: Customer email address to search for
statement: |
  SELECT id, name, email, created_at
  FROM customers
  WHERE email = $1
  LIMIT 10
```

**Tool types include:**
- `postgres-sql` / `postgres-execute-sql` / `postgres-list-tables`
- `mysql-sql` / `mongodb-find-one` / `bigquery-sql`
- `redis-get` / `elasticsearch-search`
- Many more per database type

### 4.3 Toolsets

A **Toolset** groups tools together so an agent loads a focused set of capabilities.

```yaml
kind: toolsets
name: customer_support_tools
tools:
  - search_customers_by_email
  - get_order_history
  - get_support_tickets
---
kind: toolsets
name: analytics_tools
tools:
  - get_revenue_by_month
  - get_top_products
  - get_user_cohorts
```

**Agent loads a toolset:**
```python
tools = await client.load_toolset("customer_support_tools")
```

**MCP client connects to a specific toolset:**
```json
{
  "mcpServers": {
    "toolbox": {
      "type": "http",
      "url": "http://127.0.0.1:5000/mcp/customer_support_tools"
    }
  }
}
```

### 4.4 AuthServices

**AuthServices** handle authentication and authorization. Currently supports Google Sign-In (OIDC/OAuth 2.0).

```yaml
kind: authServices
name: my_google_auth
type: google
clientId: ${GOOGLE_CLIENT_ID}
```

Used in two ways:
1. **Authorized Invocations** — require a valid auth token to call a tool at all
2. **Authenticated Parameters** — auto-populate a parameter from the OIDC token claim (e.g., `user_id` from `sub`)

```yaml
kind: tools
name: get_my_orders
type: postgres-sql
source: my-pg-source
# Tool can ONLY be called with a valid token
authRequired:
  - my_google_auth
statement: |
  SELECT * FROM orders WHERE user_id = $1
parameters:
  - name: user_id
    type: string
    description: Auto-populated from Google login — user cannot override this
    authServices:
      - name: my_google_auth
        field: sub        # the OIDC claim field; "sub" = stable user ID
```

### 4.5 Prompts

**Prompts** define reusable LLM message templates, useful for giving agents context about how to use the tools.

```yaml
kind: prompts
name: data_analyst_system_prompt
description: "System prompt for data analyst agent"
messages:
  - content: |
      You are a data analyst assistant. When querying data:
      1. Always use the provided tools, never make up data
      2. For aggregations, clarify the time period with the user
      3. Explain results in plain language
arguments:
  - name: "database_name"
    description: "The name of the database being queried"
```

---

## 5. Configuration: tools.yaml

The `tools.yaml` file is the heart of Toolbox. It supports **multiple YAML documents** in one file (separated by `---`).

### Full Example

```yaml
# ── AuthServices ──────────────────────────────────────────
kind: authServices
name: google_auth
type: google
clientId: ${GOOGLE_CLIENT_ID}

---
# ── Sources ────────────────────────────────────────────────
kind: sources
name: production-pg
type: postgres
host: ${PG_HOST}
port: 5432
database: ${PG_DATABASE}
user: ${PG_USER}
password: ${PG_PASSWORD}

---
kind: sources
name: analytics-bq
type: bigquery
project: ${GCP_PROJECT}

---
# ── Tools ──────────────────────────────────────────────────
kind: tools
name: list_tables
type: postgres-list-tables
source: production-pg
description: List all tables in the production database

---
kind: tools
name: query_orders
type: postgres-sql
source: production-pg
authRequired:
  - google_auth
description: Get orders for the currently logged-in user
statement: |
  SELECT id, status, total, created_at
  FROM orders
  WHERE user_id = $1
  ORDER BY created_at DESC
  LIMIT $2
parameters:
  - name: user_id
    type: string
    description: Auto-populated from auth token
    authServices:
      - name: google_auth
        field: sub
  - name: limit
    type: integer
    description: Number of orders to return (max 100)
    default: 10
    maxValue: 100

---
# ── Toolsets ───────────────────────────────────────────────
kind: toolsets
name: user_data_tools
tools:
  - list_tables
  - query_orders
```

### Running the server

```bash
# Binary
./toolbox --config tools.yaml

# NPM (convenience, not for production)
npx @toolbox-sdk/server --config tools.yaml

# Docker
docker run -v $(pwd)/tools.yaml:/app/tools.yaml \
  gcr.io/cloud-toolbox/toolbox:latest --config /app/tools.yaml

# Prebuilt (instant, no config)
npx @toolbox-sdk/server --prebuilt=postgres
```

Toolbox **hot-reloads** `tools.yaml` by default — no restart needed when you change the config.

### Endpoints

| Endpoint | Purpose |
|----------|---------|
| `http://localhost:5000/mcp` | MCP endpoint — all tools |
| `http://localhost:5000/mcp/{toolset_name}` | MCP endpoint — specific toolset |
| `http://localhost:5000/api/tool/{tool_name}` | Direct REST call to a tool |
| `http://localhost:5000/` + `--ui` flag | Interactive UI for testing |

---

## 6. Connecting Agents to Toolbox

### Option A: MCP Protocol (standard, any MCP client)

```json
{
  "mcpServers": {
    "toolbox": {
      "type": "http",
      "url": "http://127.0.0.1:5000/mcp"
    }
  }
}
```

### Option B: Python Toolbox SDK (recommended for ADK/LangChain)

```bash
pip install toolbox-core
```

```python
from toolbox_core import ToolboxClient

async with ToolboxClient("http://127.0.0.1:5000") as client:
    # Load all tools
    tools = await client.load_toolset()

    # Load a specific toolset
    tools = await client.load_toolset("user_data_tools")

    # Load with auth token getter (for authRequired tools)
    tools = await client.load_toolset(
        "user_data_tools",
        auth_token_getters={"google_auth": get_user_id_token}
    )
```

### Option C: LangChain / LangGraph

```python
from toolbox_langchain import ToolboxClient

client = ToolboxClient("http://127.0.0.1:5000")
tools = await client.aload_toolset("my_toolset")
```

### Option D: ADK Integration

```python
from toolbox_core import ToolboxClient
from google.adk.agents import Agent

async def create_agent_with_db_tools():
    client = ToolboxClient("http://127.0.0.1:5000")
    tools = await client.load_toolset("my_toolset")

    agent = Agent(
        name="database_agent",
        model="gemini-2.0-flash",
        tools=tools,  # pass Toolbox tools directly to ADK agent
        instruction="You help users query their database..."
    )
    return agent
```

---

## 7. Supported Databases (Sources)

### Google Cloud
| Database | Source Type |
|----------|------------|
| AlloyDB for PostgreSQL | `alloydb-postgres` |
| BigQuery | `bigquery` |
| Cloud SQL (PostgreSQL) | `cloud-sql-postgres` |
| Cloud SQL (MySQL) | `cloud-sql-mysql` |
| Cloud SQL (SQL Server) | `cloud-sql-mssql` |
| Spanner | `spanner` |
| Firestore | `firestore` |
| Bigtable | `bigtable` |

### Open Source / Self-Hosted
| Database | Source Type |
|----------|------------|
| PostgreSQL | `postgres` |
| MySQL | `mysql` |
| MariaDB | `mariadb` |
| MongoDB | `mongodb` |
| Redis / Valkey | `redis` / `valkey` |
| Elasticsearch | `elasticsearch` |
| SQLite | `sqlite` |
| SQL Server | `mssql` |
| Oracle | `oracle` |
| CockroachDB | `cockroachdb` |
| ClickHouse | `clickhouse` |
| Cassandra | `cassandra` |
| Neo4j | `neo4j` |
| Snowflake | `snowflake` |
| TiDB | `tidb` |
| Trino | `trino` |
| Couchbase | `couchbase` |
| YugabyteDB | `yugabytedb` |
| MindsDB | `mindsdb` |
| SingleStore | `singlestore` |
| HTTP (REST APIs) | `http` |

---

## 8. Security Model

### Layered security approach

```
Layer 1: AuthRequired — valid OIDC token required to call tool at all
Layer 2: AuthenticatedParams — user identity auto-injected, LLM cannot override
Layer 3: Prepared Statements — parameters bound as values, not concatenated SQL
Layer 4: allowedValues/excludedValues — input validation on parameters
Layer 5: Toolsets — agents only get the tools they need (least privilege)
```

### Why this matters for production

**UNSAFE (prebuilt `execute_sql`):**
```
Agent: "SELECT * FROM users" → executes arbitrary SQL → data exfiltration risk
```

**SAFE (custom `postgres-sql` tool):**
```
Agent: calls get_my_orders → Toolbox injects user_id from auth token →
executes pre-written "SELECT ... WHERE user_id = $1" → only user's own data
```

### Parameter types by trust level

| Type | Who provides value | Trust |
|------|--------------------|-------|
| `parameters` (basic) | LLM / agent | Medium — validate with `allowedValues` |
| `templateParameters` | LLM / agent | Low — SQL injection risk, use `allowedValues` |
| `authServices` params | OIDC token | High — user cannot override |

---

## 9. Integration Strategy for AgentForge

Given that AgentForge lets **users configure and connect to their own databases**, here is the recommended integration strategy:

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AgentForge Platform                       │
│                                                              │
│  ┌──────────────────┐        ┌──────────────────────────┐  │
│  │  Custom Frontend  │        │   AgentForge Backend     │  │
│  │  (Next.js)        │        │   (FastAPI / ADK)        │  │
│  │                  │        │                          │  │
│  │  DB Config UI    │──POST──▶  /api/connections        │  │
│  │  (host, port,    │        │  → writes tools.yaml     │  │
│  │   creds, type)   │        │  → restarts/reloads      │  │
│  └──────────────────┘        │    Toolbox server        │  │
│                              └──────────┬───────────────┘  │
│                                         │                   │
│                              ┌──────────▼───────────────┐  │
│                              │   MCP Toolbox Server     │  │
│                              │   (Go binary, port 5000) │  │
│                              │                          │  │
│                              │   sources: [user DBs]    │  │
│                              │   tools: [auto-gen]      │  │
│                              │   toolsets: [per user]   │  │
│                              └──────────┬───────────────┘  │
│                                         │                   │
│                              ┌──────────▼───────────────┐  │
│                              │      User Databases      │  │
│                              │  PG / MySQL / Mongo ...  │  │
│                              └──────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Core design decisions

1. **One shared Toolbox server** per deployment environment
2. **Dynamic tools.yaml generation** — AgentForge backend writes/rewrites `tools.yaml` when users add/remove DB connections
3. **Toolbox hot-reload** handles config changes without downtime
4. **Per-user toolsets** — each user's agent only loads their toolset
5. **Store credentials securely** in AgentForge DB, inject as env vars at Toolbox startup

---

## 10. Multi-User / Multi-Tenant Architecture

### Pattern: Per-user toolsets with shared sources

Each user gets:
- Named sources (e.g., `user_123_pg`, `user_123_mysql`)
- Named toolsets (e.g., `user_123_tools`)
- Isolated access via toolset URL: `/mcp/user_123_tools`

```yaml
# Generated tools.yaml (excerpt for two users)

kind: sources
name: user_abc_postgres
type: postgres
host: ${USER_ABC_PG_HOST}
database: ${USER_ABC_PG_DB}
user: ${USER_ABC_PG_USER}
password: ${USER_ABC_PG_PASSWORD}

---
kind: sources
name: user_xyz_mysql
type: mysql
host: ${USER_XYZ_MYSQL_HOST}
database: ${USER_XYZ_MYSQL_DB}
user: ${USER_XYZ_MYSQL_USER}
password: ${USER_XYZ_MYSQL_PASSWORD}

---
kind: tools
name: user_abc_list_tables
type: postgres-list-tables
source: user_abc_postgres
description: List all tables in user ABC's database

---
kind: toolsets
name: user_abc_toolset
tools:
  - user_abc_list_tables
  - user_abc_execute_sql

---
kind: toolsets
name: user_xyz_toolset
tools:
  - user_xyz_list_tables
  - user_xyz_execute_sql
```

**Agent for user ABC connects to:**
```
http://localhost:5000/mcp/user_abc_toolset
```

**Agent for user XYZ connects to:**
```
http://localhost:5000/mcp/user_xyz_toolset
```

---

## 11. Dynamic Config Generation Pattern

Since AgentForge needs to handle user-configured connections dynamically, here is the recommended Python pattern for generating `tools.yaml`:

```python
# backend/api/mcp_config_generator.py

import yaml
import os
from pathlib import Path
from typing import List
from pydantic import BaseModel

class DBConnection(BaseModel):
    user_id: str
    connection_name: str
    db_type: str          # postgres, mysql, mongodb, etc.
    host: str
    port: int
    database: str
    username: str
    password: str         # stored encrypted in AgentForge DB

def generate_tools_yaml(connections: List[DBConnection]) -> str:
    """Generate a tools.yaml from active user DB connections."""
    docs = []

    for conn in connections:
        source_name = f"{conn.user_id}_{conn.connection_name}"
        env_prefix = source_name.upper().replace("-", "_")

        # Source definition
        source = {
            "kind": "sources",
            "name": source_name,
            "type": conn.db_type,
            "host": f"${{{env_prefix}_HOST}}",
            "port": conn.port,
            "database": f"${{{env_prefix}_DB}}",
            "user": f"${{{env_prefix}_USER}}",
            "password": f"${{{env_prefix}_PASSWORD}}",
        }
        docs.append(source)

        # Auto-generate prebuilt tools for the source
        list_tool_name = f"{source_name}_list_tables"
        list_tool = {
            "kind": "tools",
            "name": list_tool_name,
            "type": f"{conn.db_type}-list-tables",
            "source": source_name,
            "description": f"List all tables in {conn.connection_name}",
        }
        docs.append(list_tool)

        exec_tool_name = f"{source_name}_execute_sql"
        exec_tool = {
            "kind": "tools",
            "name": exec_tool_name,
            "type": f"{conn.db_type}-execute-sql",
            "source": source_name,
            "description": f"Execute SQL against {conn.connection_name}",
        }
        docs.append(exec_tool)

        # Per-user toolset
        toolset = {
            "kind": "toolsets",
            "name": f"{conn.user_id}_toolset",
            "tools": [list_tool_name, exec_tool_name],
        }
        docs.append(toolset)

    return "---\n".join(yaml.dump(doc, default_flow_style=False) for doc in docs)


def write_tools_yaml(connections: List[DBConnection], path: Path = Path("tools.yaml")):
    """Write generated config to disk. Toolbox hot-reloads automatically."""
    content = generate_tools_yaml(connections)
    path.write_text(content)
    # Toolbox picks up the change automatically (hot-reload is on by default)
```

**Injecting secrets as environment variables** (never hardcode in YAML):

```python
def build_toolbox_env(connections: List[DBConnection]) -> dict:
    """Build environment variables for Toolbox process."""
    env = os.environ.copy()
    for conn in connections:
        prefix = f"{conn.user_id}_{conn.connection_name}".upper().replace("-", "_")
        env[f"{prefix}_HOST"] = conn.host
        env[f"{prefix}_DB"] = conn.database
        env[f"{prefix}_USER"] = conn.username
        env[f"{prefix}_PASSWORD"] = decrypt_password(conn.password)
    return env
```

---

## 12. Example: User Configures a DB Connection

### Step-by-step flow

**1. User fills in DB connection form in AgentForge UI:**
```
Database Type: PostgreSQL
Host: my-db.example.com
Port: 5432
Database: production
Username: readonly_user
Password: ••••••••
Connection Name: prod-pg
```

**2. AgentForge backend saves the connection (encrypted) and regenerates `tools.yaml`:**
```python
# POST /api/connections
new_connection = DBConnection(
    user_id="user_123",
    connection_name="prod-pg",
    db_type="postgres",
    host="my-db.example.com",
    port=5432,
    database="production",
    username="readonly_user",
    password=encrypt(raw_password),
)
db.save(new_connection)

all_connections = db.get_all_active_connections()
write_tools_yaml(all_connections, path=TOOLBOX_CONFIG_PATH)
# Toolbox auto-reloads — no restart needed
```

**3. Agent session starts — agent loads the user's toolset:**
```python
async def create_session_agent(user_id: str):
    client = ToolboxClient("http://localhost:5000")
    tools = await client.load_toolset(f"{user_id}_toolset")

    agent = ADKAgent(
        tools=tools,
        instruction="You have access to the user's configured databases..."
    )
    return agent
```

**4. User chats with agent:**
```
User: "What tables are in my production database?"
Agent: → calls user_123_prod-pg_list_tables
Toolbox: → executes against prod-pg source
Response: "I found 12 tables: orders, customers, products..."

User: "Show me the last 5 orders"
Agent: → calls user_123_prod-pg_execute_sql with
         "SELECT * FROM orders ORDER BY created_at DESC LIMIT 5"
Toolbox: → executes prepared query
Response: "Here are your last 5 orders..."
```

---

## 13. What AgentForge Needs to Build

### Backend tasks

| Task | Description | Priority |
|------|-------------|----------|
| **DB Connection Model** | Store encrypted connection configs (host, port, db, user, password, type) | P0 |
| **tools.yaml Generator** | Python service that generates valid YAML from stored connections | P0 |
| **Toolbox Process Manager** | Start/stop/monitor the Go Toolbox binary as a subprocess | P0 |
| **Connection Test Endpoint** | Validate DB credentials before saving (can use Toolbox `--prebuilt` for quick test) | P1 |
| **Secret Management** | Encrypt DB passwords at rest, inject as env vars only at runtime | P0 |
| **Per-user Toolset Routing** | Pass correct toolset URL to each user's agent session | P0 |
| **Toolbox Health Check** | Monitor Toolbox server health, restart on failure | P1 |
| **Connection CRUD API** | REST endpoints for add/list/delete/test DB connections | P1 |

### Frontend tasks

| Task | Description | Priority |
|------|-------------|----------|
| **DB Connection Form** | Fields: db type selector, host, port, database, username, password, name | P0 |
| **Connection List UI** | Show active connections with status indicators | P1 |
| **Test Connection Button** | Ping the backend to verify credentials work | P1 |
| **Tool Explorer** | Show what tools/tables the agent can access for a connection | P2 |

### Questions to answer in design

1. **Isolation level**: Shared Toolbox server with per-user toolsets, or one Toolbox process per user? (Start with shared, migrate if needed)
2. **Prebuilt vs. custom tools**: Start with `execute_sql` prebuilt for flexibility, add custom tools as user defines "saved queries"
3. **Auth strategy**: For accessing user data safely in shared mode, use `authRequired` + `authServices` OIDC authenticated params
4. **Config storage**: Store the generated `tools.yaml` on disk (Toolbox reads it) AND the structured config in PostgreSQL (source of truth for regeneration)
5. **Secret rotation**: If users change their DB password, regenerate `tools.yaml` and rotate env vars

---

## References

- [MCP Toolbox GitHub](https://github.com/googleapis/genai-toolbox)
- [Full Documentation](https://mcp-toolbox.dev)
- [Sources Reference](https://mcp-toolbox.dev/resources/sources/)
- [Tools Reference](https://mcp-toolbox.dev/resources/tools/)
- [AuthServices Reference](https://mcp-toolbox.dev/resources/authservices/)
- [Python SDK](https://github.com/googleapis/mcp-toolbox-sdk-python)
- [JS/TS SDK](https://github.com/googleapis/mcp-toolbox-sdk-js)
- [Getting Started (Python + ADK)](https://mcp-toolbox.dev/getting-started/local_quickstart/)
- [Prebuilt Tools Reference](https://mcp-toolbox.dev/reference/prebuilt-tools/)
