"""Model backends.

Default is a deterministic mock so the prototype runs anywhere with no API keys and no
data leaving the machine. Set SAFELANE_LLM_URL to any OpenAI-compatible endpoint
(e.g. a local Ollama at http://localhost:11434/v1) to use a real model.
"""
from __future__ import annotations

import os


def mock_answer(prompt: str, tool_id: str) -> str:
    preview = prompt if len(prompt) < 160 else prompt[:157] + "..."
    return (
        f"[mock reply from '{tool_id}'] I received this request:\n\n> {preview}\n\n"
        "In a live deployment, the model's answer would appear here. The model only ever saw "
        "placeholders; the gateway swapped the real values back in for you."
    )


def ask(prompt: str, tool_id: str) -> str:
    url = os.getenv("SAFELANE_LLM_URL")
    if not url:
        return mock_answer(prompt, tool_id)
    import httpx  # only needed for a real model; keeps the in-browser build dependency-free

    model = os.getenv("SAFELANE_LLM_MODEL", "qwen3:4b-instruct")
    r = httpx.post(
        f"{url.rstrip('/')}/chat/completions",
        headers={"Authorization": f"Bearer {os.getenv('SAFELANE_LLM_KEY', 'none')}"},
        json={"model": model, "messages": [{"role": "user", "content": prompt}]},
        timeout=120,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]
