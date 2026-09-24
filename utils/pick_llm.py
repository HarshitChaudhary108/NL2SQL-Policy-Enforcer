import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq

load_dotenv(override=True)

def pickllm(level: str):
    api_key = os.environ["GROQ_API_KEY"]

    if level.lower() == "low":
        model = "openai/gpt-oss-20b"
    elif level.lower() in {"medium", "hard"}:
        model = "openai/gpt-oss-120b"
    else:
        raise ValueError(f"Unsupported level: {level}")

    return ChatGroq(
        model=model,
        api_key=api_key
    )