import os
import psycopg2
import psycopg2.extras

from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
from langchain_core.prompts import ChatPromptTemplate

from utils.database import DatabaseUtil
from utils.pick_llm import pickllm

from agent.state.agent_state import AgentSchema, GatewaySchema
from gateway.policy_engine_layer_02 import GATEWAY_LAYER
from gateway.threat_detector_layer_01 import ThreatDetector

from extract_json import _extract_json

import logging
logger = logging.getLogger(__name__)

gateway01 = ThreatDetector()
gateway02 = GATEWAY_LAYER(policy_dir="policy/roles")

def curate_question_node(state: AgentSchema) -> AgentSchema:
    user_question = state["user_question"]
    llm = pickllm("low")
    threat_detector = gateway01.scan_prompt(user_question)
    if threat_detector.detected:
            return {"Threat_Layer_01": threat_detector.detected, "Threat_Type":threat_detector.threat_type}
    
    response = llm.invoke(f"curate the following question: {user_question}")
    state["curated_ques"] = response.content
    state["messages"] = [HumanMessage(content=f"{response}")]

    return state

def router_layer_01(state: AgentSchema):
    threat = state["Threat_Layer_01"]
    if threat: 
        return "INVALID"
    else:
        return "PASS"

def prompt_query_node(state: AgentSchema) -> AgentSchema:
    curated_question = state["curated_ques"]
    conn_details = {
        "host": os.environ["host"],
        "password": os.environ["password"],
        "port": os.environ["port"],
        "user": os.environ["user"],
        "database": os.environ["database"]
    }
    db_obj = DatabaseUtil(conn_details)
    schema_info = db_obj.schema_details(schema_name="public")
    prompt = f"""
    You are a PostgreSQL query generator embedded inside an automated pipeline.
    Your output is passed directly into cursor.execute() by a program — no human
    reads or edits it first. Anything other than a bare SQL statement will crash
    the pipeline with a syntax error.
 
    TASK
    Convert the user's question into exactly one ready-to-run PostgreSQL statement,
    using the schema details provided below (table names, column names, data types,
    sample rows). Unless the user explicitly asks for a specific number of rows,
    limit results to 10 rows.
 
    OUTPUT RULES (violating any of these breaks the pipeline)
    1. Output the SQL statement and absolutely nothing else.
    2. Do not wrap it in a code block. Do not use triple backticks anywhere.
    3. Do not write the word "sql" anywhere in your response.
    4. Do not add labels, headings, or lead-ins such as "Query:", "Answer:", or
       "Here is the SQL query:".
    5. Do not add comments or explanation before or after the statement.
    6. The first character you output must be the first letter of the SQL
       keyword itself (S, U, I, D, W, ...). The last character you output must
       be the statement's closing semicolon. Nothing precedes or follows it —
       not a space, not a newline, not a period.
 
    --- EXAMPLE 1 ---
    User's Original Query: show me the 5 most recent completed payments
    Response (this is the entire, exact response):
    SELECT * FROM payments WHERE payment_status = 'completed' ORDER BY payment_time DESC LIMIT 5;
 
    --- EXAMPLE 2 ---
    User's Original Query: mark payment for user 5455 as refunded
    Response (this is the entire, exact response):
    UPDATE payments SET payment_status = 'refunded' WHERE user_id = 5455;
    --- END EXAMPLES ---
 
    Now respond to the request below in exactly the same format as the examples
    above — the SQL statement alone, nothing before it and nothing after it.
 
    User's Original Query: {curated_question}
 
    Database Schema Details:
    {schema_info}
    """

    state["prompt_query"] = prompt
    return state

def generate_sql_query_node(state: AgentSchema) -> AgentSchema:
    prompt = state["prompt_query"]
    llm = pickllm("hard")
    generated_sql_query = llm.invoke(prompt)

    state["generated_sql_query"] = generated_sql_query.content

    return state

def security_gateway(state: AgentSchema):
    generated_sql_query = state["generated_sql_query"]
    prompt = ChatPromptTemplate.from_messages([
        (
            "system",
            """
            You are a SQL security-analysis assistant.
            Your response must always be a valid json object — nothing else.

            Analyze the SQL query and extract:
            1. Every SQL command used (SELECT, INSERT, UPDATE, DELETE, DROP, etc.)
            2. Every table name referenced

            Respond ONLY with this exact json structure, no markdown, no explanation:
            {{"command": ["SELECT"], "tables": ["table_name"]}}

            Rules:
            - Commands must be uppercase
            - Each table name returned only once, exactly as written
            - If no tables found, return empty list
            """
        ),
        (
            "human",
            "Return a json analysis of this SQL query:\n\n{generated_sql_query}"
        )
    ])
    role = state["role"]
    llm = pickllm(level="hard")

    try:
        # ✅ Raw invoke — no with_structured_output, no Groq API flags triggered
        chain = prompt | llm
        raw_response = chain.invoke({"generated_sql_query": generated_sql_query})
        raw_text = raw_response.content
        logger.debug(f"[gateway] Raw LLM response: {raw_text!r}")

        parsed = _extract_json(raw_text)

        configs = GatewaySchema(
            command=parsed.get("command", []),
            tables=parsed.get("tables", [])
        )
        logger.info(f"[gateway] Parsed configs: {configs}")

    except Exception as e:
        logger.error(f"[gateway] Failed to parse SQL analysis: {e}")
        #Fail secure — block execution if query cannot be analyzed
        return {
            "gateway_decision": False,
            "gateway_report": f"Security gateway could not analyze SQL query: {e}"
        }

    decision = gateway02.evaluate(command=configs.command, tables=configs.tables, role=role)
    return {
        "gateway_decision": decision["permitted"],
        "gateway_report": decision["reason"]
    }

def router_layer_02(state: AgentSchema):
    decision = state["gateway_decision"]
    if decision:
        return "PASS"
    else:
        return "INVALID"

def execute_sql_query_node(state: AgentSchema) -> AgentSchema:
    sql_query = state["generated_sql_query"]
    conn_details = {
        "host": os.environ["host"],
        "password": os.environ["password"],
        "port": os.environ["port"],
        "user": os.environ["user"],
        "database": os.environ["database"]
    }
   
    conn = None
    cursor = None
    max_rows = 20
    try:
        db_obj = DatabaseUtil(conn_details)
        conn= db_obj.conn
        cursor=conn.cursor(cursor_factory= psycopg2.extras.RealDictCursor)
        cursor.execute(sql_query)
        if cursor.description is not None:
            # SELECT (or anything with a result set, e.g. UPDATE ... RETURNING).
            # Enforced independently of whatever LIMIT (if any) is inside the
            # LLM-generated SQL — fetchmany caps what the app pulls off the wire.
            result = cursor.fetchmany(max_rows)
            state["sql_execution_result"] = result
        else:
            # UPDATE / DELETE / ALTER / etc. have no result set to fetch —
            # calling fetchmany/fetchall here raises "no results to fetch".
            # Report rows affected instead, and commit so the write persists
            # (writes silently roll back on connection close otherwise).
            rows_affected = cursor.rowcount
            conn.commit()
            state["sql_execution_result"] = {"rows_affected": rows_affected}
    except Exception as e:
        if conn:
            conn.rollback()
        state["sql_execution_result"] = f"Error occurred while executing SQL query: {e}"
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
 
    return state

def represent_final_answer(state: AgentSchema) -> AgentSchema:
    execution_result = state["sql_execution_result"]
    curated_question = state["curated_ques"]

    llm = pickllm("medium")

    prompt = f"""
    You are an SQL analyst agent. Your task is to provide a final answer to the user based on the
    execution result of the SQL query and the user's original question. The final answer should be
    concise, clear, and directly address the user's query. Avoid including any SQL code or technical
    details in the final answer. The final answer should be in a user-friendly format that is easy to
    understand. If the execution result is empty or does not provide a clear answer to the user's question,
    explain this in the final answer.
    Here is the execution result: {execution_result} \n
    Here is the user's original question: {curated_question}
    """

    llm_response = llm.invoke(prompt).content  # Get the final answer from the LLM

    state["final_answer"] = llm_response
    state["messages"] = state["messages"] + [AIMessage(content=f"{llm_response}")]  # Append the final answer to the messages list

    return state

