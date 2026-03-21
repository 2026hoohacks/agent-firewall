"""Load and manage AgentGuard policy configuration."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Optional

import yaml

from agentguard.models import PolicyConfig

_DEFAULT_POLICY_PATH = Path(__file__).parent / "default_policy.yaml"


class ConfigLoader:
    """Loads, caches, and allows runtime updates to policy configuration."""

    def __init__(self, config_path: Optional[str] = None) -> None:
        self._path = Path(config_path) if config_path else _DEFAULT_POLICY_PATH
        self._config: Optional[PolicyConfig] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self) -> PolicyConfig:
        """Load (or reload) the policy config from disk."""
        with open(self._path, "r") as fh:
            raw = yaml.safe_load(fh) or {}
        self._config = PolicyConfig(**raw)
        return self._config

    def get(self) -> PolicyConfig:
        """Return the current config, loading from disk on first access."""
        if self._config is None:
            return self.load()
        return self._config

    def update(self, partial: dict) -> PolicyConfig:
        """Merge *partial* into the current config and return the result."""
        current = self.get()
        merged = current.model_dump()
        merged.update(partial)
        self._config = PolicyConfig(**merged)
        return self._config

    def reset(self) -> PolicyConfig:
        """Reset to the on-disk defaults."""
        return self.load()

    def snapshot(self) -> dict:
        """Return a deep-copy dict of the current config."""
        return copy.deepcopy(self.get().model_dump())


# Module-level singleton for convenience.
_loader = ConfigLoader()


def get_config() -> PolicyConfig:
    """Return the global policy config."""
    return _loader.get()


def update_config(partial: dict) -> PolicyConfig:
    """Update the global policy config."""
    return _loader.update(partial)


def reset_config() -> PolicyConfig:
    """Reset the global policy config to defaults."""
    return _loader.reset()
