import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "generator"))
sys.path.insert(0, str(ROOT / "tests"))

import generate  # noqa: E402
from fortios import FortiGate, load  # noqa: E402
from model import build  # noqa: E402


@pytest.fixture(scope="session")
def model():
    import os
    if not os.environ.get("SKIP_GENERATE"):   # mutation testing tampers with configs/
        generate.main([])                     # normally: always test freshly generated configs
    return build()


@pytest.fixture(scope="session")
def fgs(model):
    return {s.code: FortiGate(load(ROOT / "configs" / f"{s.code}-fortigate.conf"))
            for s in model.sites}


def pytest_collection_modifyitems(items):
    for it in items:
        it.add_marker(pytest.mark.filterwarnings("ignore::DeprecationWarning"))
