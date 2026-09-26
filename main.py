"""
Enterprise Secure Data Access Gateway — FastAPI Backend
=======================================================

REST API for the LangGraph NL2SQL agent and its dual-layer security gateway.

Endpoints
---------
GET  /health
    Backend health check.

GET  /roles
    Returns roles loaded by the Layer 02 policy engine.

POST /query
    Executes the complete LangGraph pipeline:

        user question
              |
              v
        Layer 01 Threat Detector
              |
              v
        question curation
              |
              v
        schema/prompt construction
              |
              v
        SQL generation
              |
              v
        Layer 02 Policy Gateway
              |
          +---+---+
          |       |
       BLOCK    PASS
                  |
                  v
             PostgreSQL
                  |
                  v
             final answer

The API intentionally keeps Streamlit completely separate.  Run this
file with Uvicorn and run the Streamlit application in a second process.
"""

import logging
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from agent.graph.agent_graph import app as agent_app
from agent.nodes.agent_nodes import gateway02


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("enterprise-secure-gateway")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Enterprise Secure Data Access Gateway",
    description=(
        "Natural-language SQL agent protected by a dual-layer security "
        "gateway: Layer 01 threat detection and Layer 02 deterministic "
        "role/policy enforcement."
    ),
    version="1.0.0",
)


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class QueryRequest(BaseModel):
    role: str = Field(..., min_length=1)
    question: str = Field(..., min_length=1)


class QueryResponse(BaseModel):
    final_answer: str = ""
    generated_sql_query: str = ""
    sql_execution_result: Any = None

    # Layer 02
    gateway_decision: bool
    gateway_report: str = ""

    # Layer 01
    threat_detected: bool
    threat_type: str = ""

    # Flow control
    blocked_at: Optional[str] = None

    # Extra pipeline evidence for the Streamlit console.
    # These are returned from the real LangGraph state; the API does not
    # fabricate pipeline information.
    curated_question: str = ""
    prompt_query: str = ""


# ---------------------------------------------------------------------------
# Health / metadata endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> dict[str, str]:
    """Simple liveness endpoint used by the Streamlit console."""
    return {"status": "ok"}


@app.get("/roles")
def list_roles() -> dict[str, list[str]]:
    """
    Return the actual role names loaded by the Layer 02 policy engine.
    """
    return {"roles": sorted(gateway02.policies.keys())}


# ---------------------------------------------------------------------------
# Main query endpoint
# ---------------------------------------------------------------------------

@app.post("/query", response_model=QueryResponse)
def run_query(payload: QueryRequest) -> QueryResponse:
    """
    Run a natural-language question through the complete LangGraph graph.

    Layer 01 blocks prompt injection before SQL generation.

    Layer 02 evaluates the generated SQL against the selected role's
    deterministic YAML policy. Only a permitted query reaches PostgreSQL.
    """

    question = payload.question.strip()
    role = payload.role.strip()

    if not question:
        raise HTTPException(
            status_code=400,
            detail="question must not be empty",
        )

    if role not in gateway02.policies:
        raise HTTPException(
            status_code=400,
            detail=f"unknown role: {role}",
        )

    initial_state = {
        "role": role,
        "messages": [],
        "user_question": question,
        "curated_ques": "",
        "prompt_query": "",
        "Threat_Layer_01": False,
        "Threat_Type": "",
        "gateway_decision": True,
        "gateway_report": "",
        "generated_sql_query": "",
        "sql_execution_result": "",
        "final_answer": "",
    }

    try:
        final_state = agent_app.invoke(initial_state)
    except Exception as exc:
        logger.exception("LangGraph invocation failed")
        raise HTTPException(
            status_code=500,
            detail=f"Agent failed: {exc}",
        ) from exc

    # -----------------------------------------------------------------------
    # Normalize Layer 01 / Layer 02 state.
    # -----------------------------------------------------------------------

    threat_detected = bool(
        final_state.get("Threat_Layer_01", False)
    )

    gateway_decision = bool(
        final_state.get("gateway_decision", True)
    )

    blocked_at: Optional[str] = None

    if threat_detected:
        blocked_at = "threat_layer"
    elif not gateway_decision:
        blocked_at = "policy_gateway"

    # -----------------------------------------------------------------------
    # Final answer
    #
    # The graph ends immediately when either security layer blocks a request,
    # so final_answer can legitimately be empty on a blocked execution.
    # The API converts that into a useful user-facing message.
    # -----------------------------------------------------------------------

    final_answer = (
        final_state.get("final_answer")
        or ""
    ).strip()

    threat_type = (
        final_state.get("Threat_Type")
        or ""
    ).strip()

    gateway_report = (
        final_state.get("gateway_report")
        or ""
    ).strip()

    if not final_answer:
        if blocked_at == "threat_layer":
            final_answer = (
                "Blocked before SQL generation — possible prompt injection "
                f"({threat_type or 'unknown'})."
            )

        elif blocked_at == "policy_gateway":
            final_answer = (
                "Blocked by policy gateway — "
                f"{gateway_report or 'not permitted'}."
            )

    generated_sql = (
        final_state.get("generated_sql_query")
        or ""
    )

    curated_question = (
        final_state.get("curated_ques")
        or ""
    )

    prompt_query = (
        final_state.get("prompt_query")
        or ""
    )

    return QueryResponse(
        final_answer=final_answer,
        generated_sql_query=generated_sql,
        sql_execution_result=final_state.get(
            "sql_execution_result"
        ),
        gateway_decision=gateway_decision,
        gateway_report=gateway_report,
        threat_detected=threat_detected,
        threat_type=threat_type,
        blocked_at=blocked_at,
        curated_question=curated_question,
        prompt_query=prompt_query,
    )


# ---------------------------------------------------------------------------
# Optional local entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )
