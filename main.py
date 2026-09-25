import logging
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from agent.graph.agent_graph import app as agent_app
from agent.nodes.agent_nodes import gateway02

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nl2sql-api")

app = FastAPI(title="NL2SQL Policy Enforcer API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class QueryRequest(BaseModel):
    role: str
    question: str


class QueryResponse(BaseModel):
    final_answer: str
    generated_sql_query: str
    sql_execution_result: Any
    gateway_decision: bool
    gateway_report: str
    threat_detected: bool
    threat_type: str
    blocked_at: Optional[str] = None  # "threat_layer" | "policy_gateway" | None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/roles")
def list_roles():
    """Role names as declared inside the policy/roles/*.yml files (not the
    filenames — e.g. sr_finance_manager.yml declares role: senior_finance_manager)."""
    return {"roles": sorted(gateway02.policies.keys())}


@app.post("/query", response_model=QueryResponse)
def run_query(payload: QueryRequest):
    if not payload.question.strip():
        raise HTTPException(status_code=400, detail="question must not be empty")
    if payload.role not in gateway02.policies:
        raise HTTPException(status_code=400, detail=f"unknown role: {payload.role}")

    initial_state = {
        "role": payload.role,
        "messages": [],
        "user_question": payload.question,
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
    except Exception as e:
        logger.exception("Agent graph invocation failed")
        raise HTTPException(status_code=500, detail=f"Agent failed: {e}")

    threat_detected = bool(final_state.get("Threat_Layer_01", False))
    gateway_decision = bool(final_state.get("gateway_decision", True))

    # The graph short-circuits to END on either layer, so `final_answer`
    # stays empty on a block. Fill in something user-facing for those cases.
    blocked_at = None
    if threat_detected:
        blocked_at = "threat_layer"
    elif not gateway_decision:
        blocked_at = "policy_gateway"

    final_answer = final_state.get("final_answer") or ""
    if not final_answer:
        if blocked_at == "threat_layer":
            final_answer = (
                f"Blocked before SQL generation — possible prompt injection "
                f"({final_state.get('Threat_Type', 'unknown')})."
            )
        elif blocked_at == "policy_gateway":
            final_answer = f"Blocked by policy gateway — {final_state.get('gateway_report', 'not permitted')}."

    return QueryResponse(
        final_answer=final_answer,
        generated_sql_query=final_state.get("generated_sql_query") or "",
        sql_execution_result=final_state.get("sql_execution_result"),
        gateway_decision=gateway_decision,
        gateway_report=final_state.get("gateway_report") or "",
        threat_detected=threat_detected,
        threat_type=final_state.get("Threat_Type") or "",
        blocked_at=blocked_at,
    )