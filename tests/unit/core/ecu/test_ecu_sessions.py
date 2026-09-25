from pathlib import Path

import pytest

from ddt4all.core.ecu.ecu_data import EcuData
from ddt4all.core.ecu.ecu_file import EcuFile
from ddt4all.core.ecu.ecu_request import EcuRequest
from ddt4all.core.ecu.ecu_sessions import (
    DEFAULT_SESSION_LABEL,
    DEFAULT_SESSION_STREAM,
    list_diag_sessions,
)

EXAMPLES_DIR = Path(__file__).resolve().parents[4] / "tests" / "resources" / "configuration"


def make_ecu_file(requests, data=None):
    ecu = EcuFile(None)
    for name, value in (data or {}).items():
        ecu.data[name] = EcuData(value, name)
    for req in requests:
        r = EcuRequest(req, ecu)
        ecu.requests[r.name] = r
    return ecu


def test_default_session_when_no_session_request():
    ecu = make_ecu_file([{"name": "ReadA", "sentbytes": "2101"}])
    sessions, default = list_diag_sessions(ecu)
    assert sessions == [(DEFAULT_SESSION_LABEL, DEFAULT_SESSION_STREAM)]
    assert default == "10C0"


def test_extended_session_becomes_default():
    ecu = make_ecu_file([
        {"name": "StartDiagnosticSession.Default", "sentbytes": "1001"},
        {"name": "StartDiagnosticSession.Extended", "sentbytes": "1003"},
        {"name": "StartDiagnosticSession.Reprog", "sentbytes": "1002"},
    ])
    sessions, default = list_diag_sessions(ecu)
    assert default == "1003"
    assert sessions[0] == (DEFAULT_SESSION_LABEL, DEFAULT_SESSION_STREAM)
    assert ("StartDiagnosticSession.Extended [1003]", "1003") in sessions
    assert ("StartDiagnosticSession.Reprog [1002]", "1002") in sessions


def test_session_name_data_item_expands_list_values():
    ecu = make_ecu_file(
        [{"name": "StartDiagnosticSession", "sentbytes": "1000",
          "sendbyte_dataitems": {"Session Name": {"firstbyte": 2}}}],
        {"Session Name": {"bitscount": 8, "lists": {"192": "afterSales", "3": "extendedDiagnosticSession"}}},
    )
    sessions, default = list_diag_sessions(ecu)
    labels = [s[0] for s in sessions]
    assert "afterSales [10C0]" in labels
    assert "extendedDiagnosticSession [1003]" in labels
    assert default == "1003"


@pytest.mark.skipif(not EXAMPLES_DIR.exists(), reason="tests/resources/configuration/ directory not available")
@pytest.mark.parametrize("prefix, expected", [("MFD_", "10C0"), ("A_IVI_", "1003"), ("A_IVI2_", "1003")])
def test_sessions_on_example_definitions(prefix, expected):
    files = sorted(EXAMPLES_DIR.glob(prefix + "*.json"))
    assert files, "no example file for %s" % prefix
    ecu = EcuFile(str(files[0]), isfile=True)
    assert ecu.requests
    _, default = list_diag_sessions(ecu)
    assert default == expected
