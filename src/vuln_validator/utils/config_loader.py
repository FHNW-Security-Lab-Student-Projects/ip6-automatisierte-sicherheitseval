from __future__ import annotations

import copy
import logging
from pathlib import Path
from typing import Any, Dict, Optional

import tomllib

logger = logging.getLogger(__name__)

_DEFAULTS: Dict[str, Any] = {
    "solver": {
        "base_memory": {
            "max_steps": 500,
            "step_size": 1,
        }
    }
}

_CONFIG_CACHE: Optional[Dict[str, Any]] = None


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            base[k] = _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def _coerce_positive_int(value: Any, default: int, name: str) -> int:
    try:
        value_int = int(value)
        if value_int <= 0:
            raise ValueError
        return value_int
    except Exception:
        logger.warning(
            "Invalid %s=%r in config. Using default %d.", name, value, default
        )
        return default


def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None:
        return _CONFIG_CACHE

    cfg = copy.deepcopy(_DEFAULTS)
    cfg_path = (
        Path(path) if path else Path(__file__).resolve().parents[3] / "config.toml"
    )

    if not cfg_path.exists():
        logger.info("Config file not found at %s. Using defaults.", cfg_path)
        _CONFIG_CACHE = cfg
        return cfg

    try:
        with open(cfg_path, "rb") as f:
            loaded = tomllib.load(f)
    except Exception as e:
        logger.warning(
            "Failed to load config file %s: %s. Using defaults.", cfg_path, e
        )
        _CONFIG_CACHE = cfg
        return cfg

    _CONFIG_CACHE = _deep_merge(cfg, loaded)
    return _CONFIG_CACHE


def get_base_memory_solver_config(path: Optional[str] = None) -> Dict[str, int]:
    cfg = load_config(path)
    defaults = _DEFAULTS["solver"]["base_memory"]
    section = cfg.get("solver", {}).get("base_memory", {})

    max_steps = _coerce_positive_int(
        section.get("max_steps", defaults["max_steps"]),
        defaults["max_steps"],
        "solver.base_memory.max_steps",
    )
    step_size = _coerce_positive_int(
        section.get("step_size", defaults["step_size"]),
        defaults["step_size"],
        "solver.base_memory.step_size",
    )

    return {"max_steps": max_steps, "step_size": step_size}
