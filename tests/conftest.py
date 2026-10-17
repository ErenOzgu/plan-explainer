import json
from pathlib import Path

import pytest

from plan_explainer.analysis import analyse
from plan_explainer.model import parse

from .fakes import FakeAnthropic

ROOT = Path(__file__).resolve().parent.parent
PLANS = ROOT / "examples" / "plans"


def analysis_of(path):
    return analyse(parse(Path(path).read_text()))


@pytest.fixture(scope="session")
def webshop():
    return analysis_of(PLANS / "webshop.json")


@pytest.fixture(scope="session")
def tidy():
    return analysis_of(PLANS / "tidy.json")


@pytest.fixture
def anthropic():
    servers = []

    def make(reply="", status=200):
        s = FakeAnthropic(reply, status)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.close()


def write_plan(tmp_path, doc, name="plan.json"):
    p = tmp_path / name
    p.write_text(json.dumps(doc))
    return p
