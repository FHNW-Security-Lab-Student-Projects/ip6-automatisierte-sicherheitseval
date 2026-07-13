import copy
import pytest

from vuln_validator.utils import config_loader


@pytest.fixture
def set_config(monkeypatch):
    def _set_config(**analyzer_overrides):
        cfg = copy.deepcopy(config_loader._DEFAULTS)
        cfg["analyzer"].update(analyzer_overrides)
        monkeypatch.setattr(
            config_loader,
            "load_config",
            lambda *args, **kwargs: copy.deepcopy(cfg),
        )

    return _set_config
