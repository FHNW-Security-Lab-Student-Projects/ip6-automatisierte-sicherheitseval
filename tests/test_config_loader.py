import textwrap

import vuln_validator.utils.config_loader as config_loader


def _set_fake_config_root(monkeypatch, tmp_path):
    """Sets a temporary config root for testing purposes."""
    monkeypatch.setattr(
        config_loader,
        "_config_path",
        lambda: tmp_path / "config.toml",
    )
    config_loader._CONFIG_CACHE = None
    return tmp_path


def _write_config(root, content: str):
    """
    Writes a configuration file to the specified root directory.
    """
    (root / "config.toml").write_text(textwrap.dedent(content))
    config_loader._CONFIG_CACHE = None


def test_config_loader_defaults_when_missing(monkeypatch, tmp_path):
    """
    Test that the configuration loader returns default values when the config file is missing.
    """
    _set_fake_config_root(monkeypatch, tmp_path)

    # no config.toml written on purpose
    cfg = config_loader.get_config()

    assert cfg["solver"]["base_memory"]["simulation"]["max_steps"] == 500
    assert cfg["solver"]["base_memory"]["simulation"]["step_size"] == 1
    assert cfg["solver"]["base_memory"]["input"]["symbolic_stdin_bytes"] == 512
    assert cfg["solver"]["memory_layout"]["heap_start"] == 0x2000000
    assert cfg["solver"]["memory_layout"]["arg_start"] == 0x3000000
    assert cfg["analyzer"]["auto_stop_on_first_found"] is False
    assert cfg["analyzer"]["specific_stop_on_first_found"] is True
    assert cfg["analyzer"]["specific_continue_on_no_find"] is False
    assert cfg["analyzer"]["continue_on_error"] is False


def test_config_loader_overrides(monkeypatch, tmp_path):
    """
    Test that the configuration loader correctly overrides default values with those specified in the config file.
    """
    root = _set_fake_config_root(monkeypatch, tmp_path)
    _write_config(
        root,
        """
        [solver.base_memory.simulation]
        max_steps = 123
        step_size = 2

        [solver.base_memory.input]
        symbolic_stdin_bytes = 64

        [solver.memory_layout]
        heap_start = 0x2220000
        arg_start = 0x3330000

        [analyzer]
        auto_stop_on_first_found = true
        specific_stop_on_first_found = false
        specific_continue_on_no_find = true
        continue_on_error = true

        [logging]
        log_level = "DEBUG"
        """,
    )

    cfg = config_loader.get_config()

    assert cfg["solver"]["base_memory"]["simulation"]["max_steps"] == 123
    assert cfg["solver"]["base_memory"]["simulation"]["step_size"] == 2
    assert cfg["solver"]["base_memory"]["input"]["symbolic_stdin_bytes"] == 64
    assert cfg["solver"]["memory_layout"]["heap_start"] == 0x2220000
    assert cfg["solver"]["memory_layout"]["arg_start"] == 0x3330000
    assert cfg["analyzer"]["auto_stop_on_first_found"] is True
    assert cfg["analyzer"]["specific_stop_on_first_found"] is False
    assert cfg["analyzer"]["specific_continue_on_no_find"] is True
    assert cfg["analyzer"]["continue_on_error"] is True
    assert cfg["logging"]["log_level"] == "DEBUG"


def test_config_loader_invalid_values_fallback(monkeypatch, tmp_path):
    """
    Test that the configuration loader falls back to default values when invalid values are provided in the config file.
    """
    root = _set_fake_config_root(monkeypatch, tmp_path)
    _write_config(
        root,
        """
        [solver.base_memory.simulation]
        max_steps = -1
        step_size = "bad"

        [solver.base_memory.input]
        symbolic_stdin_bytes = 0

        [solver.memory_layout]
        heap_start = "nope"
        arg_start = "nope"

        [analyzer]
        auto_stop_on_first_found = "no"
        specific_stop_on_first_found = "no"
        specific_continue_on_no_find = "no"
        continue_on_error = "no"
        """,
    )

    cfg = config_loader.get_config()

    assert cfg["solver"]["base_memory"]["simulation"]["max_steps"] == 500
    assert cfg["solver"]["base_memory"]["simulation"]["step_size"] == 1
    assert cfg["solver"]["base_memory"]["input"]["symbolic_stdin_bytes"] == 512
    assert cfg["solver"]["memory_layout"]["heap_start"] == 0x2000000
    assert cfg["solver"]["memory_layout"]["arg_start"] == 0x3000000
    assert cfg["analyzer"]["auto_stop_on_first_found"] is False
    assert cfg["analyzer"]["specific_stop_on_first_found"] is True
    assert cfg["analyzer"]["specific_continue_on_no_find"] is False
    assert cfg["analyzer"]["continue_on_error"] is False
