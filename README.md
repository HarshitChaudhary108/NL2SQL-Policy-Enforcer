# Query Authorization Gateway

A policy-enforced control plane for AI-driven SQL execution. This project wraps a natural-language-to-SQL agent (built with LangGraph) in a role-based security gateway, so that an LLM can translate user questions into SQL and run them against a PostgreSQL database **without** being able to bypass access-control rules — even if the generated query is malformed, unexpected, or adversarial.

## Why this exists

LLM-generated SQL is powerful but unpredictable: a model can hallucinate a `DELETE`, touch a table it shouldn't, or drift outside the intent of the user's question. This project treats that risk as a first-class problem by inserting a deterministic, YAML-driven **policy gateway** between SQL generation and SQL execution. The gateway does not use an LLM to decide whether a query is safe — it parses the query's declared commands/tables and checks them against a per-role allow/deny list, failing closed (blocking execution) whenever the check itself cannot be completed with confidence.

## How it works

The system is a [LangGraph](https://github.com/langchain-ai/langgraph) state graph with the following flow:

```
START
  │
  ▼
curate_question        # LLM cleans up / clarifies the raw user question
  │
  ▼
prompt_query            # Builds an SQL-generation prompt using live DB schema
  │
  ▼
generate_sql_query       # LLM generates a Postgres SQL query
  │
  ▼
gateway (security_gateway)   # LLM extracts {commands, tables} from the SQL,
  │                            then a deterministic policy engine evaluates it
  │
  ├── PASS ──► execute_sql_query ──► represent_final_answer ──► END
  │
  └── INVALID ──► END   (query is blocked, never reaches the database)
```

1. **`curate_question`** — refines the user's raw natural-language question.
2. **`prompt_query`** — fetches live schema details (tables, columns, sample rows) from PostgreSQL and builds a grounded prompt for SQL generation.
3. **`generate_sql_query`** — an LLM converts the question into a ready-to-run Postgres query.
4. **`security_gateway`** — a second LLM call extracts the SQL commands and tables referenced in the generated query as structured JSON; this is then checked deterministically against the requesting role's policy file. If the query cannot be parsed/analyzed, the gateway fails secure and blocks execution.
5. **`router`** — routes to execution only if the gateway decision is `PASS`; otherwise the run ends with a rejection reason.
6. **`execute_sql_query`** — runs the approved query against PostgreSQL.
7. **`represent_final_answer`** — an LLM turns the raw result set into a natural-language answer for the user.

## Role-based policy engine

Access rules live as YAML files under `policy/roles/` (see `policy/roles/analyst.yml` for an example) and are loaded and enforced by `gateway/layer.py`. Each role definition specifies:

- **`allowed_tools`** — which tools the role may use at all (currently `sql`).
- **`allowed_operations`** — whitelisted SQL commands (e.g. `SELECT`).
- **`blocked_patterns`** — explicitly blacklisted commands (e.g. `DROP`, `DELETE`, `UPDATE`, `INSERT`, `TRUNCATE`, `ALTER`) checked as defense-in-depth on top of the whitelist.
- **`allowed_tables`** / **`blocked_tables`** — per-table access control.
- **`max_rows`** — a data-exfiltration limit on returned rows.

The evaluation logic is **fail-secure by design**: unknown roles, disallowed tools, non-whitelisted commands, and non-whitelisted tables are all rejected by default, with blacklists layered on top rather than relied upon alone.

## Project structure

```
.
├── agent/
│   ├── graph/
│   │   └── agent_graph.py      # LangGraph graph definition and wiring
│   ├── nodes/
│   │   └── agent_nodes.py      # Node implementations (curate, generate, gateway, execute, answer)
│   └── state/
│       └── agent_state.py      # Typed state schemas (AgentSchema, GatewaySchema)
├── gateway/
│   └── layer.py                 # Deterministic policy evaluation engine
├── policy/
│   └── roles/
│       └── analyst.yml          # Example role-based access policy
├── utils/
│   ├── database.py              # PostgreSQL connection + schema introspection
│   └── pick_llm.py              # Groq LLM selection helper (low/medium/hard)
├── extract_json.py              # Robust JSON extraction from LLM responses
├── feed_data.py                 # Creates schema + seeds tables from CSVs in data/
├── main.py                      # Entry point placeholder
└── pyproject.toml
```

## Prerequisites

- Python >= 3.12
- [uv](https://github.com/astral-sh/uv) (project uses a `uv.lock` file) or `pip`
- A PostgreSQL database
- A [Groq](https://groq.com/) API key (the agent uses `langchain-groq` models: `openai/gpt-oss-20b` and `openai/gpt-oss-120b`)

## Installation

```bash
git clone https://github.com/HarshitChaudhary108/Query-Authorization-Gateway.git
cd Query-Authorization-Gateway

# using uv
uv sync

# or using pip
pip install -e .
```

## Configuration

Create a `.env` file in the project root with your database and LLM credentials:

```env
GROQ_API_KEY=your_groq_api_key

host=your_db_host
port=your_db_port
user=your_db_user
password=your_db_password
database=your_db_name
```

## Database setup

The example schema models a ride-hailing platform (`users`, `vehicles`, `rides`, `payments`, `ratings`). To create the tables and load sample data:

1. Place your CSV files (`users.csv`, `vehicles.csv`, `rides.csv`, `payments.csv`, `ratings.csv`) in a `data/` directory at the project root.
2. Run:

```bash
python feed_data.py
```

This creates the schema (if it doesn't exist), loads each CSV via `COPY`, prints record counts, and commits the transaction.

## Usage

Run the agent graph directly:

```bash
python -m agent.graph.agent_graph
```

By default, `agent_graph.py` runs with a sample question and role of `analyst`, and prints the gateway decision, the reason, the final natural-language answer, the generated SQL, and the raw execution result.

To use it programmatically:

```python
from agent.graph.agent_graph import app

initial_state = {
    "messages": [],
    "user_question": "what is the average rating given by riders in the last month?",
    "curated_ques": "",
    "prompt_query": "",
    "gateway_decision": True,
    "gateway_report": "",
    "generated_sql_query": "",
    "sql_execution_result": "",
    "final_answer": ""
}

final_state = app.invoke(initial_state)
print(final_state["final_answer"])
```

### Example: a blocked query

Given the `analyst` policy (read-only access to `ratings` and `payments`; no access to `users`, `rides`, or `vehicles`; only `SELECT` permitted), a request like *"update the user id of user 5455 to '29122024'"* is generated as an `UPDATE` statement, caught by the gateway, and rejected before it ever reaches the database — the run ends with `gateway_decision = False` and a explanatory `gateway_report`.

## Adding a new role

Add a new YAML file under `policy/roles/`, e.g. `policy/roles/admin.yml`:

```yaml
role: admin
version: "1.0"

allowed_tools:
  - sql

tools:
  sql:
    allowed_operations:
      - SELECT
      - INSERT
      - UPDATE
    blocked_patterns:
      - "DROP"
      - "TRUNCATE"
    max_rows: 5000
    allowed_tables:
      - users
      - rides
      - vehicles
      - payments
      - ratings
    blocked_tables: []
```

Policies are loaded automatically at startup from `policy/roles/*.yml`; no code changes are required.

## Tech stack

- [LangGraph](https://github.com/langchain-ai/langgraph) — agent orchestration as a state graph
- [LangChain](https://github.com/langchain-ai/langchain) + [langchain-groq](https://pypi.org/project/langchain-groq/) — LLM integration (Groq-hosted `gpt-oss` models)
- [psycopg2](https://www.psycopg.org/) — PostgreSQL driver
- [PyYAML](https://pyyaml.org/) — policy file parsing
- [python-dotenv](https://pypi.org/project/python-dotenv/) — environment configuration

## License

No license file is currently included in this repository. Add one (e.g. MIT, Apache-2.0) if you intend for others to use or contribute to this project.
