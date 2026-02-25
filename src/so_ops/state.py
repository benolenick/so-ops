"""Per-tool state persistence: cursor + run history."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


MAX_HISTORY = 50


class ToolState:
    """Manages JSON state file for a single tool."""

    def __init__(self, tool_name: str, state_dir: Path):
        state_dir.mkdir(parents=True, exist_ok=True)
        self.path = state_dir / f"{tool_name}.json"
        self._data = self._load()
        self._start_time: float | None = None

    def _load(self) -> dict:
        if self.path.exists():
            with open(self.path) as f:
                raw = json.load(f)
            # Migrate old format: top-level last_timestamp + int runs
            if "cursor" not in raw:
                cursor = {}
                if "last_timestamp" in raw:
                    cursor["last_timestamp"] = raw.pop("last_timestamp")
                raw.pop("total_processed", None)
                raw.pop("last_run", None)
                old_runs = raw.pop("runs", 0)
                raw = {"cursor": cursor, "runs": []}
            elif not isinstance(raw.get("runs"), list):
                raw["runs"] = []
            return raw
        return {"cursor": {}, "runs": []}

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self._data, f, indent=2)

    # --- Cursor (arbitrary key-value for tool-specific position) ---

    def get_cursor(self, key: str, default=None):
        return self._data.get("cursor", {}).get(key, default)

    def set_cursor(self, key: str, value):
        self._data.setdefault("cursor", {})[key] = value
        self.save()

    # --- Run tracking ---

    def start_run(self):
        self._start_time = time.monotonic()

    def finish_run(self, **extra):
        duration = (time.monotonic() - self._start_time) if self._start_time else 0
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration": round(duration, 1),
            **extra,
        }
        runs = self._data.setdefault("runs", [])
        runs.append(entry)
        # Keep only the last MAX_HISTORY entries
        if len(runs) > MAX_HISTORY:
            self._data["runs"] = runs[-MAX_HISTORY:]
        self.save()

    def last_run(self) -> dict | None:
        runs = self._data.get("runs", [])
        if not isinstance(runs, list) or not runs:
            return None
        return runs[-1]

    def as_status_line(self) -> str:
        """One-line status for `so-ops status`."""
        last = self.last_run()
        if not last:
            return "never run"
        ts = last["timestamp"]
        dur = last.get("duration", "?")
        extras = {k: v for k, v in last.items() if k not in ("timestamp", "duration")}
        parts = [f"Last run {ts} ({dur}s)"]
        for k, v in extras.items():
            parts.append(f"{k}={v}")
        return " — ".join(parts)
