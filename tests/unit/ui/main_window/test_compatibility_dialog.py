import pytest

pytest.importorskip("pytestqt")
core = pytest.importorskip("PyQt5.QtCore")

from ddt4all.core.ecu.ecu_compatibility import (  # noqa: E402
    RESULT_FAIL,
    RESULT_NOT_TESTABLE,
    RESULT_PASS,
    CompatibilityReport,
    CompatibilityResult,
    DefinitionGroup,
    ScannedEcuIdentity,
)
from ddt4all.core.ecu.ecu_ident import EcuIdent  # noqa: E402
from ddt4all.core.ecu.ecu_scanner import EcuScanner  # noqa: E402
from ddt4all.ui.main_window.compatibility_dialog import COL_SELECT, CompatibilityDialog  # noqa: E402


def make_ident(name, href, soft="00A5"):
    return EcuIdent("14", "213", soft, "8300", name, "GRP", href, "CAN", ["X95"], "58")


def make_result(status, name, members=()):
    rep = make_ident(name, name + ".json")
    group = DefinitionGroup(representative=rep,
                            members=[rep] + [make_ident(m, m + ".json") for m in members],
                            hrefs=[rep.href], ecu_file=None, signature=name, session_stream="10C0")
    return CompatibilityResult(group, status, [], "")


@pytest.fixture
def report():
    identity = ScannedEcuIdentity("58", "CAN", "14", "213", "243C", "2931", "X95", 0)
    return CompatibilityReport(identity=identity, results=[
        make_result(RESULT_PASS, "MFD v5.4", members=["MFD v5.3", "MFD v5.2"]),
        make_result(RESULT_FAIL, "MFD v4"),
        make_result(RESULT_NOT_TESTABLE, "MFD v3"),
    ])


def test_only_pass_representatives_are_checkable(qtbot, report):
    dialog = CompatibilityDialog([report])
    qtbot.addWidget(dialog)
    ecu_item = dialog.tree.topLevelItem(0)
    assert ecu_item.childCount() == 3
    pass_item, fail_item, nt_item = (ecu_item.child(i) for i in range(3))
    assert pass_item.flags() & core.Qt.ItemIsUserCheckable
    assert not fail_item.flags() & core.Qt.ItemIsUserCheckable
    assert not nt_item.flags() & core.Qt.ItemIsUserCheckable
    # member rows: no checkbox, no selection
    assert pass_item.childCount() == 2
    for i in range(2):
        child = pass_item.child(i)
        assert not child.flags() & core.Qt.ItemIsUserCheckable
        assert not child.flags() & core.Qt.ItemIsSelectable
    assert dialog.selected_results() == []


def test_selected_results_and_scanner_integration(qtbot, report):
    dialog = CompatibilityDialog([report])
    qtbot.addWidget(dialog)
    pass_item = dialog.tree.topLevelItem(0).child(0)
    pass_item.setCheckState(COL_SELECT, core.Qt.Checked)
    chosen = dialog.selected_results()
    assert [r.group.representative.name for r in chosen] == ["MFD v5.4"]

    scanner = EcuScanner.__new__(EcuScanner)
    scanner.ecus = {}
    scanner.approximate_ecus = {}
    scanner.compatible_ecus = {}
    scanner.num_ecu_found = 0
    assert scanner.add_compatible(chosen[0]) is True
    assert scanner.add_compatible(chosen[0]) is False      # no double insertion
    assert list(scanner.compatible_ecus) == ["MFD v5.4"]
    assert scanner.ecus == {}
    assert scanner.num_ecu_found == 1
