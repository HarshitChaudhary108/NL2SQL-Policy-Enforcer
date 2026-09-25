from langgraph.graph import StateGraph, START, END
from agent.state.agent_state import AgentSchema
from agent.nodes.agent_nodes import (
    curate_question_node,
    prompt_query_node,
    generate_sql_query_node,
    execute_sql_query_node,
    represent_final_answer,
    security_gateway,
    router_layer_02,
    router_layer_01
)


graph = StateGraph(AgentSchema)
graph.add_node("curate_question", curate_question_node)
graph.add_node("prompt_query", prompt_query_node)
graph.add_node("generate_sql_query", generate_sql_query_node)
graph.add_node("gateway", security_gateway)
graph.add_node("execute_sql_query", execute_sql_query_node)
graph.add_node("represent_final_answer", represent_final_answer)

graph.add_edge(START, "curate_question")
graph.add_conditional_edges(
    "curate_question", router_layer_01, {
        "PASS": "prompt_query",
        "INVALID": END
    })
graph.add_edge("prompt_query", "generate_sql_query")
graph.add_edge("generate_sql_query", "gateway")
graph.add_conditional_edges(
    "gateway", router_layer_02, {
        "PASS": "execute_sql_query",
        "INVALID": END
    }
)
graph.add_edge("execute_sql_query", "represent_final_answer")
graph.add_edge("represent_final_answer", END)

app = graph.compile()


if __name__ == "__main__":
    initial_state = {
        "role": "analyst",
        "messages": [],
        "user_question": "Total sum of Payments done by the user with id = 5455?",
        "curated_ques": "",
        "prompt_query": "",
        "Threat_Layer_01": False,
        "Threat_Type": "",
        "gateway_decision": True,
        "gateway_report": "",
        "generated_sql_query": "",
        "sql_execution_result": "",
        "final_answer": ""
    }

    final_state = app.invoke(initial_state)
    print(f"Gateway Decision: {final_state["gateway_decision"]}")
    print("="*20)
    print(f"Gateway Reasons: {final_state["gateway_report"]}")
    print("="*20)
    print(f"Final Answer: {final_state["final_answer"]}")
    print("="*20)
    print(f"Generated SQL Query: {final_state["generated_sql_query"]}")
    print("="*20)
    print(f"SQL Execution Result: {final_state["sql_execution_result"]}")
    print("="*20)
    print(f"Threat Signal: {final_state["Threat_Layer_01"]}")
    print("="*20)
    print(f"Threat Type: {final_state["Threat_Type"]}")
    