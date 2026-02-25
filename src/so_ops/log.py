"""Structured logging: stderr + rotating .log + append-only .jsonl."""

from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import datetime, timezone
from pathlib import Path


class JsonlHandler(logging.Handler):
    """Append-only JSONL audit log. Never rotated."""

    def __init__(self, path: Path):
        super().__init__()
        self.path = path

    def emit(self, record: logging.LogRecord):
        try:
            entry = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "msg": record.getMessage(),
            }
            # Merge any extra structured fields
            for key in ("alert_id", "verdict", "source_ip", "dest_ip",
                        "dest_port", "rule_name", "reason", "recommendation",
                        "method", "duration", "count"):
                val = getattr(record, key, None)
                if val is not None:
                    entry[key] = val
            with open(self.path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            self.handleError(record)


def setup_logging(tool_name: str, log_dir: Path) -> logging.Logger:
    """Configure 3-destination logging for a tool.

    Returns a logger with:
      1. stderr (captured by systemd journal)
      2. Rotating .log file (5MB x 3 backups)
      3. Append-only .jsonl file (structured audit trail)
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(f"so-ops.{tool_name}")
    logger.setLevel(logging.DEBUG)

    # Avoid duplicate handlers on repeated calls
    if logger.handlers:
        return logger

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    # 1. stderr
    stderr_h = logging.StreamHandler()
    stderr_h.setLevel(logging.INFO)
    stderr_h.setFormatter(fmt)
    logger.addHandler(stderr_h)

    # 2. Rotating file
    file_h = logging.handlers.RotatingFileHandler(
        log_dir / f"{tool_name}.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
    )
    file_h.setLevel(logging.DEBUG)
    file_h.setFormatter(fmt)
    logger.addHandler(file_h)

    # 3. JSONL audit trail
    jsonl_h = JsonlHandler(log_dir / f"{tool_name}.jsonl")
    jsonl_h.setLevel(logging.INFO)
    logger.addHandler(jsonl_h)

    return logger
