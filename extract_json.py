import json
import re

def _extract_json(text: str) -> dict:
    """Robustly extract JSON from LLM response regardless of formatting."""
    if not text or not text.strip():
        raise ValueError("LLM returned an empty response")

    # Strategy 1: Direct parse
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        pass

    # Strategy 2: Extract first {...} block via regex
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    # Strategy 3: Strip markdown fences, then parse
    cleaned = re.sub(r'```(?:json)?|```', '', text).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    raise ValueError(f"Could not extract valid JSON.\nRaw: {text!r}")
