# DB-MCP Documentation

Custom documentation for the DB-MCP fork of [googleapis/genai-toolbox](https://github.com/googleapis/genai-toolbox).

| Document | Description |
|----------|-------------|
| [API.md](API.md) | Full REST API reference — all endpoints, request/response schemas, curl examples per tier |
| [DATABASES.md](DATABASES.md) | Supported databases — `db_type` values, connection params, SSL modes, MCP tool availability |
| [ARCHITECTURE.md](ARCHITECTURE.md) | What we changed from upstream, why, and how every piece fits together |
| [SECURITY.md](SECURITY.md) | Three security tiers (local / enterprise / SaaS) — credential flow and configuration |
| [RUNNING.md](RUNNING.md) | How to build and run the server — all CLI flags, Docker, examples for each tier |
| [MCP-TOOLBOX.md](MCP-TOOLBOX.md) | Upstream genai-toolbox reference (sources, tools, architecture overview) |

The interactive API reference is served at runtime at `http://localhost:5000/docs`.
