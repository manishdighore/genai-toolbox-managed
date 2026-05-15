# Supported Databases

This document covers every database type DB-MCP understands —
the `db_type` values, connection parameters, `extra_params` keys, and the MCP tools exposed.

---

## Support Levels

| Level | What it means |
|-------|--------------|
| **Full MCP** | Connection saved, credentials stored, `/mcp/{name}` endpoint mounted with live tools. |
| **GCP-managed** | Full MCP via upstream genai-toolbox sources, but requires GCP service account / ADC auth. Not covered here — see upstream docs. |

All databases listed below (except GCP-managed) have **Full MCP** support.

---

## Standard Relational Databases

---

### PostgreSQL

| Field | Value |
|-------|-------|
| `db_type` | `postgres` or `postgresql` |
| Default port | `5432` |
| MCP tool | `execute_sql` |
| Test query | `SELECT version()` |

**Compatible variants:** PostgreSQL 12+, Amazon RDS, Azure Database for PostgreSQL.

**Connection parameters:**

| Parameter | Required | Notes |
|-----------|----------|-------|
| `name` | yes | Unique; used as MCP endpoint path `/mcp/{name}` |
| `db_type` | yes | `postgres` |
| `host` | yes | Hostname or IP |
| `port` | yes | Default `5432` |
| `database` | yes | Database name |
| `username` | yes | Postgres role |
| `password` / `credential_token` | yes | See [SECURITY.md](SECURITY.md) |
| `ssl_mode` | no | `disable` \| `require` (default) \| `verify-full` |
| `description` | no | Human-readable label |

**Example:**
```json
{
  "name": "prod-postgres",
  "db_type": "postgres",
  "host": "db.example.com",
  "port": 5432,
  "database": "myapp",
  "username": "app_user",
  "credential_token": "ctok_...",
  "ssl_mode": "require"
}
```

---

### MySQL / MariaDB

| Field | Value |
|-------|-------|
| `db_type` | `mysql` or `mariadb` |
| Default port | `3306` |
| MCP tool | `execute_sql` |

**Compatible variants:** MySQL 5.7+, MySQL 8+, MariaDB 10.3+, Amazon RDS for MySQL, Azure Database for MySQL, TiDB.

**Connection parameters:** same as PostgreSQL with `db_type: "mysql"` and `port: 3306`.

> TiDB uses `db_type: "tidb"` — it routes through the MySQL driver automatically.

**Example:**
```json
{
  "name": "prod-mysql",
  "db_type": "mysql",
  "host": "mysql.example.com",
  "port": 3306,
  "database": "myapp",
  "username": "app_user",
  "credential_token": "ctok_..."
}
```

---

### Microsoft SQL Server

| Field | Value |
|-------|-------|
| `db_type` | `mssql`, `sqlserver`, or `sql_server` |
| Default port | `1433` |
| MCP tool | `execute_sql` |
| Test query | `SELECT @@VERSION` |

**Compatible variants:** SQL Server 2017–2022, Azure SQL Database, Azure SQL Managed Instance, Amazon RDS for SQL Server.

**Example:**
```json
{
  "name": "prod-mssql",
  "db_type": "mssql",
  "host": "sql.example.com",
  "port": 1433,
  "database": "MyDatabase",
  "username": "sa",
  "credential_token": "ctok_..."
}
```

---

### CockroachDB

| Field | Value |
|-------|-------|
| `db_type` | `cockroachdb` |
| Default port | `26257` |
| MCP tool | `execute_sql` |

CockroachDB speaks the PostgreSQL wire protocol. Use `ssl_mode: "require"` (CockroachDB Cloud enforces TLS).

**Example:**
```json
{
  "name": "prod-cockroach",
  "db_type": "cockroachdb",
  "host": "free-tier.cockroachlabs.cloud",
  "port": 26257,
  "database": "defaultdb",
  "username": "root",
  "credential_token": "ctok_...",
  "ssl_mode": "require"
}
```

---

### YugabyteDB

| Field | Value |
|-------|-------|
| `db_type` | `yugabytedb` |
| Default port | `5433` |
| MCP tool | `execute_sql` |

YugabyteDB's YSQL layer is PostgreSQL-compatible. Default port differs from Postgres (`5433`).

**Example:**
```json
{
  "name": "prod-yugabyte",
  "db_type": "yugabytedb",
  "host": "yugabyte.example.com",
  "port": 5433,
  "database": "yugabyte",
  "username": "yugabyte",
  "credential_token": "ctok_..."
}
```

---

### TiDB

| Field | Value |
|-------|-------|
| `db_type` | `tidb` |
| Default port | `4000` |
| MCP tool | `execute_sql` |

TiDB is MySQL-compatible. Internally routes through the MySQL driver.

**Example:**
```json
{
  "name": "prod-tidb",
  "db_type": "tidb",
  "host": "tidb.example.com",
  "port": 4000,
  "database": "myapp",
  "username": "root",
  "credential_token": "ctok_..."
}
```

---

### SQLite (local file)

| Field | Value |
|-------|-------|
| `db_type` | `sqlite` |
| Default port | N/A |
| MCP tool | `execute_sql` |
| Driver | `modernc.org/sqlite` (no CGO) |

For SQLite, `host` holds the **file path** to the database. No TCP dial is performed.

**Example:**
```json
{
  "name": "local-sqlite",
  "db_type": "sqlite",
  "host": "/data/myapp.db",
  "port": 0,
  "database": "main",
  "username": "",
  "password": ""
}
```

> `port`, `username`, and `password` are ignored for SQLite but must be present in the request.

---

## Analytical / OLAP Databases

---

### ClickHouse

| Field | Value |
|-------|-------|
| `db_type` | `clickhouse` |
| Default port | `9000` (native TCP), `8123` (HTTP) |
| MCP tool | `execute_sql` |

**`extra_params` keys:**

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `secure` | `"true"` / `"false"` | `"false"` | Enable TLS for the native TCP connection |

**Example:**
```json
{
  "name": "prod-clickhouse",
  "db_type": "clickhouse",
  "host": "clickhouse.example.com",
  "port": 9000,
  "database": "default",
  "username": "default",
  "credential_token": "ctok_...",
  "extra_params": {
    "secure": "true"
  }
}
```

---

### Snowflake

| Field | Value |
|-------|-------|
| `db_type` | `snowflake` |
| Default port | `443` |
| MCP tool | `execute_sql` |

Snowflake uses an account identifier instead of host/port. The `host` field holds the **account identifier** (e.g. `xy12345.us-east-1`).

**`extra_params` keys:**

| Key | Type | Required | Notes |
|-----|------|----------|-------|
| `schema` | string | no | Default schema (e.g. `PUBLIC`) |
| `warehouse` | string | no | Virtual warehouse to use (e.g. `COMPUTE_WH`) |
| `role` | string | no | Snowflake role to assume (e.g. `SYSADMIN`) |

**Example:**
```json
{
  "name": "prod-snowflake",
  "db_type": "snowflake",
  "host": "xy12345.us-east-1",
  "port": 443,
  "database": "MY_DB",
  "username": "app_user",
  "credential_token": "ctok_...",
  "extra_params": {
    "schema": "PUBLIC",
    "warehouse": "COMPUTE_WH",
    "role": "SYSADMIN"
  }
}
```

---

## Document / NoSQL Databases

---

### MongoDB

| Field | Value |
|-------|-------|
| `db_type` | `mongodb` |
| Default port | `27017` |
| MCP tool | `find` |

MongoDB Atlas and MongoDB Atlas Data API connections can provide a full connection URI via `extra_params.uri`, which overrides `host`/`port`/`username`.

**`extra_params` keys:**

| Key | Type | Required | Notes |
|-----|------|----------|-------|
| `uri` | string | no | Full MongoDB URI (e.g. `mongodb+srv://user:pass@cluster.mongodb.net`). If provided, overrides host/port/username. |

**Standard (host/port) example:**
```json
{
  "name": "prod-mongo",
  "db_type": "mongodb",
  "host": "mongo.example.com",
  "port": 27017,
  "database": "myapp",
  "username": "app_user",
  "credential_token": "ctok_..."
}
```

**Atlas SRV URI example:**
```json
{
  "name": "prod-atlas",
  "db_type": "mongodb",
  "host": "cluster0.abc.mongodb.net",
  "port": 27017,
  "database": "myapp",
  "username": "",
  "password": "",
  "extra_params": {
    "uri": "mongodb+srv://user:pass@cluster0.abc.mongodb.net/myapp?retryWrites=true&w=majority"
  }
}
```

---

### Elasticsearch

| Field | Value |
|-------|-------|
| `db_type` | `elasticsearch` |
| Default port | `9200` (HTTP) / `9243` (HTTPS) |
| MCP tool | `esql` |
| SSL | `ssl_mode: "disable"` → `http://`; anything else → `https://` |

**Example:**
```json
{
  "name": "prod-es",
  "db_type": "elasticsearch",
  "host": "es.example.com",
  "port": 9243,
  "database": "my-index",
  "username": "elastic",
  "credential_token": "ctok_...",
  "ssl_mode": "require"
}
```

---

## Graph Databases

---

### Neo4j

| Field | Value |
|-------|-------|
| `db_type` | `neo4j` |
| Default port | `7687` (Bolt) / `7474` (HTTP) |
| MCP tool | `execute_cypher` |

**`extra_params` keys:**

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `uri_scheme` | string | `"bolt"` | URI scheme: `bolt`, `bolt+s` (TLS), `neo4j`, `neo4j+s` (cluster+TLS) |

**Example (local, no TLS):**
```json
{
  "name": "prod-neo4j",
  "db_type": "neo4j",
  "host": "neo4j.example.com",
  "port": 7687,
  "database": "neo4j",
  "username": "neo4j",
  "credential_token": "ctok_...",
  "extra_params": {
    "uri_scheme": "bolt"
  }
}
```

**Example (AuraDB / TLS):**
```json
{
  "name": "prod-aura",
  "db_type": "neo4j",
  "host": "abc123.databases.neo4j.io",
  "port": 7687,
  "database": "neo4j",
  "username": "neo4j",
  "credential_token": "ctok_...",
  "extra_params": {
    "uri_scheme": "neo4j+s"
  }
}
```

---

## Wide-Column / Time-Series

---

### Cassandra / ScyllaDB

| Field | Value |
|-------|-------|
| `db_type` | `cassandra` |
| Default port | `9042` |
| MCP tool | `cql` |

Cassandra uses keyspaces instead of databases. The `database` field maps to the keyspace.

**`extra_params` keys:**

| Key | Type | Required | Notes |
|-----|------|----------|-------|
| `keyspace` | string | no | Cassandra keyspace (overrides `database` field if set) |

**Example:**
```json
{
  "name": "prod-cassandra",
  "db_type": "cassandra",
  "host": "cassandra.example.com",
  "port": 9042,
  "database": "my_keyspace",
  "username": "cassandra",
  "credential_token": "ctok_...",
  "extra_params": {
    "keyspace": "my_keyspace"
  }
}
```

---

## Cache / Key-Value Stores

---

### Redis

| Field | Value |
|-------|-------|
| `db_type` | `redis` |
| Default port | `6379` |
| MCP tool | `redis` (get/set/del/keys) |
| Probe | TCP dial + `AUTH` + `PING` |

The test fully validates the password — if `AUTH` fails the save is rejected.

**Example:**
```json
{
  "name": "prod-redis",
  "db_type": "redis",
  "host": "redis.example.com",
  "port": 6379,
  "database": "0",
  "username": "default",
  "credential_token": "ctok_..."
}
```

> `database` is unused for Redis but required by the API schema — pass `"0"`.

---

### Valkey

| Field | Value |
|-------|-------|
| `db_type` | `valkey` |
| Default port | `6379` |
| MCP tool | `valkey` (get/set/del/keys) |

Valkey is a Redis-compatible open-source fork. Configuration is identical to Redis.

**Example:**
```json
{
  "name": "prod-valkey",
  "db_type": "valkey",
  "host": "valkey.example.com",
  "port": 6379,
  "database": "0",
  "username": "default",
  "credential_token": "ctok_..."
}
```

---

## GCP-Managed Databases (requires GCP auth)

The following `db_type` values are recognized and routed to the correct upstream genai-toolbox source,
but they require a GCP service account or Application Default Credentials (ADC) configured on the server.
Connectivity testing via the REST API is not yet supported for these types.

| `db_type` | Upstream source | Notes |
|-----------|----------------|-------|
| `cloud-sql-postgres` or `cloudsqlpostgres` | `cloud-sql-postgres` | Cloud SQL for PostgreSQL via IAM |
| `cloud-sql-mysql` or `cloudsqlmysql` | `cloud-sql-mysql` | Cloud SQL for MySQL via IAM |
| `cloud-sql-mssql` or `cloudsqlmssql` | `cloud-sql-mssql` | Cloud SQL for SQL Server via IAM |
| `alloydb-postgres` or `alloydb` | `alloydb-postgres` | AlloyDB for PostgreSQL via IAM |

For these types, deploy the server with a GCP service account attached and configure the connection
the same way as their non-managed counterparts. The server will use ADC for authentication.

---

## Quick Reference

### Default Ports

| Database | Default Port |
|----------|-------------|
| PostgreSQL | 5432 |
| MySQL / MariaDB / TiDB | 3306 |
| SQL Server | 1433 |
| CockroachDB | 26257 |
| YugabyteDB | 5433 |
| SQLite | N/A (local file) |
| ClickHouse | 9000 (native), 8123 (HTTP) |
| Snowflake | 443 |
| MongoDB | 27017 |
| Elasticsearch | 9200 (HTTP), 9243 (HTTPS) |
| Neo4j | 7687 (Bolt), 7474 (HTTP) |
| Cassandra | 9042 |
| Redis / Valkey | 6379 |

### MCP Tools by Database

| Database | MCP Tool name |
|----------|--------------|
| PostgreSQL, CockroachDB, YugabyteDB, TiDB, MySQL, MariaDB, SQL Server, SQLite, Snowflake, ClickHouse | `execute_sql` |
| MongoDB | `find` |
| Elasticsearch | `esql` |
| Neo4j | `execute_cypher` |
| Cassandra | `cql` |
| Redis | `redis` |
| Valkey | `valkey` |

### SSL Modes

| `ssl_mode` | PostgreSQL | MySQL | SQL Server |
|------------|-----------|-------|-----------|
| `disable` | No TLS | No TLS | No encryption |
| `require` | TLS, cert not verified | TLS `skip-verify` | Encrypted |
| `verify-full` | TLS, cert verified | TLS `skip-verify`* | Encrypted |

*MySQL `verify-full` behaves the same as `require`. Full certificate pinning requires mounting a CA cert inside the container.

---

## Adding a Connection — Minimal curl

```bash
# Stage credentials first (local tier)
TOKEN=$(curl -s -X POST http://localhost:5001/api/credentials/stage \
  -H "Content-Type: application/json" \
  -d '{"password":"secret"}' | jq -r .credential_token)

# Create connection (substitute db_type, host, port, database, username)
curl -X POST http://localhost:5001/api/connections \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"mydb\",
    \"db_type\": \"postgres\",
    \"host\": \"localhost\",
    \"port\": 5432,
    \"database\": \"app\",
    \"username\": \"user\",
    \"credential_token\": \"$TOKEN\"
  }"
```

**MCP endpoint after saving:**
```
http://localhost:5001/mcp/mydb
```
