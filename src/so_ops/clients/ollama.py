"""Ollama LLM client."""

from __future__ import annotations

import json
import urllib.request

from so_ops.config import OllamaConfig


class OllamaClient:
    """HTTP client for local Ollama API."""

    def __init__(self, cfg: OllamaConfig):
        self._url = cfg.url.rstrip("/")
        self._model = cfg.model

    def generate(self, prompt: str, temperature: float = 0.1,
                 max_tokens: int = 2048, timeout: int = 120) -> str:
        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{self._url}/api/generate", data=data, method="POST",
        )
        req.add_header("Content-Type", "application/json")
        resp = urllib.request.urlopen(req, timeout=timeout)
        result = json.loads(resp.read().decode())
        return result.get("response", "")
