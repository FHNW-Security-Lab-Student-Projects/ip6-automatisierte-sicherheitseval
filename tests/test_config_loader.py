import textwrap

import vuln_validator.utils.config_loader as config_loader


def _set_fake_config_root(monkeypatch, tmp_path):
    monkeypatch.setattr(
        config_loader,
        "_config_path",
        lambda: tmp_path / "config.toml",
    )
    config_loader._CONFIG_CACHE = None
    return tmp_path


def _write_config(root, content: str):
    (root / "config.toml").write_text(textwrap.dedent(content))
    config_loader._CONFIG_CACHE = None


def test_config_loader_defaults_when_missing(monkeypatch, tmp_path):
    _set_fake_config_root(monkeypatch, tmp_path)

    base_cfg = config_loader.get_base_memory_solver_config()
    heap_cfg = config_loader.get_heap_hook_config()
    analyzer_cfg = config_loader.get_analyzer_config()

    assert base_cfg["max_steps"] == 500
    assert base_cfg["step_size"] == 1
    assert base_cfg["symbolic_stdin_bytes"] == 512
    assert heap_cfg["heap_start"] == 0x600000
    assert analyzer_cfg["auto_stop_on_first_found"] is False
    assert analyzer_cfg["specific_stop_on_first_found"] is True
    assert analyzer_cfg["specific_continue_on_no_find"] is True


def test_config_loader_overrides(monkeypatch, tmp_path):
    root = _set_fake_config_root(monkeypatch, tmp_path)
    _write_config(
        root,
        """
        [solver.base_memory.simulation]
        max_steps = 123
        step_size = 2

        [solver.base_memory.input]
        symbolic_stdin_bytes = 64

        [solver.heap]
        heap_start = 0x700000

        [analyzer]
        auto_stop_on_first_found = true
        specific_stop_on_first_found = false
        specific_continue_on_no_find = false
        """,
    )

    base_cfg = config_loader.get_base_memory_solver_config()
    heap_cfg = config_loader.get_heap_hook_config()
    analyzer_cfg = config_loader.get_analyzer_config()

    assert base_cfg["max_steps"] == 123
    assert base_cfg["step_size"] == 2
    assert base_cfg["symbolic_stdin_bytes"] == 64
    assert heap_cfg["heap_start"] == 0x700000
    assert analyzer_cfg["auto_stop_on_first_found"] is True
    assert analyzer_cfg["specific_stop_on_first_found"] is False
    assert analyzer_cfg["specific_continue_on_no_find"] is False


def test_config_loader_invalid_values_fallback(monkeypatch, tmp_path):
    root = _set_fake_config_root(monkeypatch, tmp_path)
    _write_config(
        root,
        """
        [solver.base_memory.simulation]
        max_steps = -1
        step_size = "bad"

        [solver.base_memory.input]
        symbolic_stdin_bytes = 0

        [solver.heap]
        heap_start = "nope"

        [analyzer]
        auto_stop_on_first_found = "no"
        specific_stop_on_first_found = "no"
        specific_continue_on_no_find = "no"
        """,
    )

    base_cfg = config_loader.get_base_memory_solver_config()
    heap_cfg = config_loader.get_heap_hook_config()
    analyzer_cfg = config_loader.get_analyzer_config()

    assert base_cfg["max_steps"] == 500
    assert base_cfg["step_size"] == 1
    assert base_cfg["symbolic_stdin_bytes"] == 512
    assert heap_cfg["heap_start"] == 0x600000
    assert analyzer_cfg["auto_stop_on_first_found"] is False
    assert analyzer_cfg["specific_stop_on_first_found"] is True
    assert analyzer_cfg["specific_continue_on_no_find"] is True
