from langgraph.graph import StateGraph, START, END
from agent.state.agent_state import AgentSchema
from agent.nodes.agent_nodes import (
    curate_question_node,
    prompt_query_node,
    generate_sql_query_node,
    execute_sql_query_node,
    represent_final_answer,
    security_gateway,
    router
)


graph = StateGraph(AgentSchema)
graph.add_node("curate_question", curate_question_node)
graph.add_node("prompt_query", prompt_query_node)
graph.add_node("generate_sql_query", generate_sql_query_node)
graph.add_node("gateway", security_gateway)
graph.add_node("execute_sql_query", execute_sql_query_node)
graph.add_node("represent_final_answer", represent_final_answer)

graph.add_edge(START, "curate_question")
graph.add_edge("curate_question", "prompt_query")
graph.add_edge("prompt_query", "generate_sql_query")
graph.add_edge("generate_sql_query", "gateway")
graph.add_conditional_edges(
    "gateway", router, {
        "PASS": "execute_sql_query",
        "INVALID": END
    }
)
graph.add_edge("execute_sql_query", "represent_final_answer")
graph.add_edge("represent_final_answer", END)

app = graph.compile()


if __name__ == "__main__":
    initial_state = {
        "messages": [],
        "user_question": "update the user id of user(id = 5455) to id ='29122024'",
        "curated_ques": "",
        "prompt_query": "",
        "gateway_decision": True,
        "gateway_report": "",
        "generated_sql_query": "",
        "sql_execution_result": "",
        "final_answer": ""
    }

    final_state = app.invoke(initial_state)
    print(final_state["gateway_decision"])
    print(final_state["gateway_report"])
    print(final_state["final_answer"])
    print(final_state["generated_sql_query"])
    print(final_state["sql_execution_result"])
    