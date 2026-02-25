"""Elasticsearch client for Security Onion."""

from __future__ import annotations

import base64
import json
import ssl
import urllib.request
from typing import Any

from so_ops.config import ESConfig


class SOElasticClient:
    """HTTP client for Security Onion Elasticsearch."""

    def __init__(self, cfg: ESConfig):
        self._host = cfg.host.rstrip("/")
        self._creds = base64.b64encode(f"{cfg.user}:{cfg.password}".encode()).decode()
        self._ssl_ctx = ssl.create_default_context()
        if not cfg.verify_ssl:
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def request(self, path: str, body: dict | None = None,
                method: str | None = None, timeout: int = 60) -> dict:
        url = self._host + path
        data = json.dumps(body).encode() if body else None
        if method is None:
            method = "POST" if body else "GET"
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Basic {self._creds}")
        if body:
            req.add_header("Content-Type", "application/json")
        resp = urllib.request.urlopen(req, context=self._ssl_ctx, timeout=timeout)
        return json.loads(resp.read().decode())

    # --- Convenience methods ---

    def search(self, index: str, body: dict, timeout: int = 60) -> dict:
        return self.request(f"/{index}/_search", body, timeout=timeout)

    def count(self, index: str, body: dict | None = None, timeout: int = 30) -> int:
        result = self.request(f"/{index}/_count", body, timeout=timeout)
        return result.get("count", 0)

    def fetch_suricata_alerts(self, since: str, max_results: int = 2000,
                              index: str = "logs-suricata.alerts-so") -> tuple[list, int]:
        """Fetch Suricata alerts since a timestamp. Returns (hits, total)."""
        query: dict[str, Any] = {
            "size": max_results,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {"range": {"@timestamp": {"gt": since}}},
        }
        result = self.search(index, query)
        hits = result.get("hits", {}).get("hits", [])
        total = result.get("hits", {}).get("total", {}).get("value", 0)
        return hits, total

    def fetch_detection_alerts(self, since: str, max_results: int = 100,
                               index: str = "logs-detections.alerts-so") -> list:
        """Fetch Sigma/detection alerts since a timestamp."""
        query: dict[str, Any] = {
            "size": max_results,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {"range": {"@timestamp": {"gt": since}}},
        }
        try:
            result = self.search(index, query)
            return result.get("hits", {}).get("hits", [])
        except Exception:
            return []

    def get_data_streams(self, pattern: str = "*so*") -> list:
        """List matching data streams."""
        try:
            result = self.request(f"/_data_stream/{pattern}")
            return result.get("data_streams", [])
        except Exception:
            return []
