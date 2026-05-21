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
            "simulation": {
                "max_steps": 500,
                "step_size": 1,
            },
            "input": {
                "symbolic_stdin_bytes": 512,
            },
        },
        "heap": {
            "heap_start": 0x600000,
        },
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


def _get_nested(d: Dict[str, Any], path: tuple[str, ...], default: Any) -> Any:
    cur: Any = d
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def load_config() -> Dict[str, Any]:
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None:
        return _CONFIG_CACHE

    cfg = copy.deepcopy(_DEFAULTS)
    cfg_path = Path(__file__).resolve().parents[3] / "config.toml"

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


def _build_solver_config(
    section_name: str, specs: list[tuple[str, tuple[str, ...], Any]]
) -> Dict[str, Any]:
    cfg = load_config()
    defaults = _DEFAULTS["solver"].get(section_name, {})
    section = cfg.get("solver", {}).get(section_name, {})

    result: Dict[str, Any] = {}
    for out_key, path, coerce in specs:
        default_val = _get_nested(defaults, path, None)
        value = _get_nested(section, path, default_val)
        name = f"solver.{section_name}." + ".".join(path)
        result[out_key] = coerce(value, default_val, name)

    return result


def get_base_memory_solver_config() -> Dict[str, Any]:
    specs = [
        ("max_steps", ("simulation", "max_steps"), _coerce_positive_int),
        ("step_size", ("simulation", "step_size"), _coerce_positive_int),
        (
            "symbolic_stdin_bytes",
            ("input", "symbolic_stdin_bytes"),
            _coerce_positive_int,
        ),
    ]
    return _build_solver_config("base_memory", specs)


def get_heap_hook_config() -> Dict[str, Any]:
    specs = [
        ("heap_start", ("heap_start",), _coerce_positive_int),
    ]
    return _build_solver_config("heap", specs)
