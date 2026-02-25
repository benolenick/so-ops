"""Shared test fixtures."""

import pytest
from pathlib import Path


@pytest.fixture
def example_config_path():
    return Path(__file__).parent.parent / "config.example.toml"


@pytest.fixture
def tmp_data_dir(tmp_path):
    """Create a temporary data directory with expected subdirs."""
    for subdir in ("state", "logs", "output/triage/summaries", "output/health", "output/vulnscan"):
        (tmp_path / subdir).mkdir(parents=True)
    return tmp_path
