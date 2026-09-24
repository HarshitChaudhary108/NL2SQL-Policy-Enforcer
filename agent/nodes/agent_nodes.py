import os
import psycopg2
import psycopg2.extras

from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
from langchain_core.prompts import ChatPromptTemplate

from utils.database import DatabaseUtil
from utils.pick_llm import pickllm

from agent.state.agent_state import AgentSchema, GatewaySchema
from gateway.layer import GATEWAY_LAYER

from extract_json import _extract_json

import logging
logger = logging.getLogger(__name__)

gateway = GATEWAY_LAYER(policy_dir="policy/roles")

def curate_question_node(state: AgentSchema) -> AgentSchema:
    user_question = state["user_question"]
    llm = pickllm("low")
    response = llm.invoke(f"curate the following question: {user_question}")
    state["curated_ques"] = response.content
    state["messages"] = [HumanMessage(content=f"{response}")] 
    return state

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
    You are an SQL analyst agent. Your task is to convert the user's natural language
    query into Postgres SQL query that can be executed on the database. You are provided
    with the user's original query and the schema details of the database, including
    table names, column names, data types, and sample data for each table so that
    you can understand the structure of the database and generate an accurate SQL query.
    Unless user explicitly asks for specific number of rows, always limit the output to 10 rows.
    Note - Just generate the SQL query without any explanation or additional text because
    this query will be executed directly on the database. So, the output should be SQL
    ready to be executed without any modifications.

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
        # ✅ Fail secure — block execution if query cannot be analyzed
        return {
            "gateway_decision": False,
            "gateway_report": f"Security gateway could not analyze SQL query: {e}"
        }

    decision = gateway.evaluate(command=configs.command, tables=configs.tables)
    return {
        "gateway_decision": decision["permitted"],
        "gateway_report": decision["reason"]
    }

def router(state: AgentSchema):
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
    try:
        db_obj = DatabaseUtil(conn_details)
        conn= db_obj.conn
        cursor=conn.cursor(cursor_factory= psycopg2.extras.RealDictCursor)
        cursor.execute(sql_query)
        result = cursor.fetchall()

        state["sql_execution_result"] = result

    except Exception as e:
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

