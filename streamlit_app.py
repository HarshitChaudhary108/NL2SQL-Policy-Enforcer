import os

import pandas as pd
import requests
import streamlit as st

BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000").rstrip("/")

st.set_page_config(page_title="NL2SQL Policy Enforcer", page_icon="🛡️", layout="centered")
st.title("🛡️ NL2SQL Policy Enforcer")
st.caption(
    "Ask a question in plain English. A role-scoped agent turns it into SQL, "
    "a two-layer security gateway checks it, and only then does it touch the database."
)


@st.cache_data(ttl=30)
def fetch_roles():
    try:
        resp = requests.get(f"{BACKEND_URL}/roles", timeout=5)
        resp.raise_for_status()
        roles = resp.json().get("roles", [])
        return roles or ["analyst", "senior_finance_manager"]
    except requests.RequestException:
        return ["analyst", "senior_finance_manager"]


with st.sidebar:
    st.subheader("Session")
    roles = fetch_roles()
    role = st.selectbox("Acting as role", roles)
    st.caption(f"Backend: {BACKEND_URL}")
    if st.button("Refresh roles"):
        fetch_roles.clear()
        st.rerun()
    if st.button("Clear history"):
        st.session_state.history = []
        st.rerun()

if "history" not in st.session_state:
    st.session_state.history = []  # newest first: [{role, question, data}, ...]

question = st.text_area(
    "Your question",
    placeholder="e.g. What is the average payment amount for completed rides?",
    height=100,
)
submit = st.button("Run query", type="primary")

if submit:
    if not question.strip():
        st.warning("Type a question first.")
    else:
        with st.spinner("Curating question → generating SQL → checking policy → executing..."):
            try:
                resp = requests.post(
                    f"{BACKEND_URL}/query",
                    json={"role": role, "question": question},
                    timeout=120,
                )
                resp.raise_for_status()
                st.session_state.history.insert(0, {"role": role, "question": question, "data": resp.json()})
            except requests.RequestException as e:
                detail = ""
                if getattr(e, "response", None) is not None:
                    try:
                        detail = f" — {e.response.json().get('detail', '')}"
                    except ValueError:
                        detail = f" — {e.response.text}"
                st.error(f"Couldn't reach the backend at {BACKEND_URL}{detail}")

for entry in st.session_state.history:
    data = entry["data"]
    blocked_at = data.get("blocked_at")

    with st.container(border=True):
        st.markdown(f"**Q ({entry['role']}):** {entry['question']}")

        if blocked_at == "threat_layer":
            st.error(f"🚫 Blocked before SQL generation — threat type: `{data.get('threat_type')}`")
        elif blocked_at == "policy_gateway":
            st.error(f"🚫 Blocked by policy gateway — {data.get('gateway_report')}")
        else:
            st.success(data.get("final_answer") or "No answer returned.")

        with st.expander("Show pipeline details"):
            st.markdown("**Generated SQL**")
            st.code(data.get("generated_sql_query") or "—", language="sql")

            st.markdown("**Gateway decision**")
            st.write(f"Permitted: `{data.get('gateway_decision')}` — {data.get('gateway_report') or '—'}")

            st.markdown("**Raw execution result**")
            result = data.get("sql_execution_result")
            if isinstance(result, list) and result and isinstance(result[0], dict):
                st.dataframe(pd.DataFrame(result), use_container_width=True)
            elif result not in (None, "", []):
                st.write(result)
            else:
                st.caption("No rows returned.")
    st.divider()