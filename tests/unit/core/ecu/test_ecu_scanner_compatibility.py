"""Integration of the third identification level inside EcuScanner (no hardware)."""

import ddt4all.options as options
from ddt4all.core.ecu import ecu_compatibility
from ddt4all.core.ecu.ecu_data import EcuData
from ddt4all.core.ecu.ecu_file import EcuFile
from ddt4all.core.ecu.ecu_ident import EcuIdent
from ddt4all.core.ecu.ecu_request import EcuRequest
from ddt4all.core.ecu.ecu_scanner import EcuScanner


class FakeLogView:
    def __init__(self):
        self.lines = []

    def append(self, line):
        self.lines.append(line)


class FakeMainWindow:
    def __init__(self):
        self.logview = FakeLogView()


class FakeTransport:
    def __init__(self, responses):
        self.responses = responses
        self.requests = []
        self.sessions = []
        self.cmds = []
        self.startSession = ""
        self.lf = 0

    def start_session_can(self, stream):
        self.sessions.append(stream)
        return True

    def request(self, req, positive='', cache=True):
        self.requests.append((req, cache))
        return self.responses.get(req, "")

    def cmd(self, command, serviceDelay="0"):
        self.cmds.append(command)
        return ""


class FakeDatabase:
    def __init__(self, targets):
        self.targets = targets
        self.addr_group_mapping = {"58": "NAV"}


def make_ecu_file():
    ecu = EcuFile(None)
    ecu.data["A"] = EcuData({"bitscount": 8, "bytescount": 1}, "A")
    for req in [
        {"name": "ReadA", "sentbytes": "22F190", "minbytes": 4, "receivebyte_dataitems": {"A": {"firstbyte": 4}}},
        {"name": "WriteA", "sentbytes": "2EF190", "sendbyte_dataitems": {"A": {"firstbyte": 4}}},
    ]:
        r = EcuRequest(req, ecu)
        ecu.requests[r.name] = r
    return ecu


def make_scanner(targets, project="X95"):
    scanner = EcuScanner.__new__(EcuScanner)
    scanner.totalecu = 0
    scanner.ecus = {}
    scanner.approximate_ecus = {}
    scanner.num_ecu_found = 0
    scanner.report_data = []
    scanner.qapp = None
    scanner.ecu_database = FakeDatabase(targets)
    scanner._reset_compatibility_state()
    scanner.current_project = project
    return scanner


def ident(name, href, soft="1111", version="0000", supplier="213", diagversion="14"):
    return EcuIdent(diagversion, supplier, soft, version, name, "NAV", href, "CAN", ["X95"], "58")


def test_check_ecu2_triggers_check_in_group_only_when_nothing_retained(mocker):
    mocker.patch.object(options, "simulation_mode", False)
    mocker.patch.object(options, "opt_compat_check", True)
    mocker.patch.object(options, "main_window", FakeMainWindow())
    transport = FakeTransport({"22F190": "62 F1 90 05"})
    mocker.patch.object(options, "elm", transport)
    mocker.patch.object(ecu_compatibility, "_default_loader", lambda href: make_ecu_file())

    targets = [ident("MFD v5.4", "mfd54.json"), ident("MFD v5.3", "mfd53.json"),
               ident("Other", "other.json", supplier="214")]
    scanner = make_scanner(targets)

    # exact match: no fallback
    scanner.check_ecu2("14", "213", "1111", "0000", None, "58", "CAN")
    assert scanner.pending_compatibility is None
    assert len(scanner.ecus) == 1

    # no exact, no approximate (different soft): fallback prepared, groups computed, no bus access yet
    scanner = make_scanner(targets)
    scanner.check_ecu2("14", "213", "243C", "2931", None, "58", "CAN")
    report = scanner.pending_compatibility
    assert report is not None
    assert [t.name for t in report.candidates] == ["MFD v5.4", "MFD v5.3"]
    assert len(report.groups) == 1                      # identical definitions merged
    assert report.groups[0].representative.name == "MFD v5.3"
    assert transport.requests == []

    # probe runs from the scan loop, after the identification session is closed
    scanner._run_pending_compatibility()
    assert scanner.pending_compatibility is None
    assert len(scanner.compatibility_reports) == 1
    result = scanner.compatibility_reports[0].results[0]
    assert result.status == "PASS"
    assert [r for r in transport.requests] == [("22F190", False)]
    assert transport.cmds == ["1081"]
    assert scanner.compatible_ecus == {}                # nothing added without user selection

    # user selection
    assert scanner.add_compatible(result) is True
    assert list(scanner.compatible_ecus) == ["MFD v5.3"]
    assert scanner.ecus == {}


def test_no_fallback_without_project_or_in_simulation_or_for_kwp(mocker):
    mocker.patch.object(options, "main_window", FakeMainWindow())
    mocker.patch.object(options, "elm", FakeTransport({}))
    mocker.patch.object(options, "opt_compat_check", True)
    targets = [ident("MFD v5.4", "mfd54.json")]

    mocker.patch.object(options, "simulation_mode", False)
    scanner = make_scanner(targets)
    mocker.patch.object(options, "opt_compat_check", False)   # option disabled at startup
    scanner.check_ecu2("14", "213", "243C", "2931", None, "58", "CAN")
    assert scanner.pending_compatibility is None
    mocker.patch.object(options, "opt_compat_check", True)

    scanner = make_scanner(targets, project=None)
    scanner.check_ecu2("14", "213", "243C", "2931", None, "58", "CAN")
    assert scanner.pending_compatibility is None

    scanner = make_scanner(targets)
    scanner.check_ecu2("14", "213", "243C", "2931", None, "58", "KWP")
    assert scanner.pending_compatibility is None

    mocker.patch.object(options, "simulation_mode", True)
    scanner = make_scanner(targets)
    scanner.check_ecu2("14", "213", "243C", "2931", None, "58", "CAN")
    assert scanner.pending_compatibility is None


def test_no_report_when_no_candidate(mocker):
    mocker.patch.object(options, "simulation_mode", False)
    mocker.patch.object(options, "opt_compat_check", True)
    mocker.patch.object(options, "main_window", FakeMainWindow())
    mocker.patch.object(options, "elm", FakeTransport({}))
    scanner = make_scanner([ident("Other", "other.json", supplier="214")])
    scanner.check_ecu2("14", "213", "243C", "2931", None, "58", "CAN")
    assert scanner.pending_compatibility is None
    scanner._run_pending_compatibility()
    assert scanner.compatibility_reports == []


def _frame(sid_hex, payload):
    return " ".join([sid_hex[i:i + 2] for i in range(0, len(sid_hex), 2)]
                    + ["%02X" % b for b in payload])


def test_identify_new_keeps_full_f195_version_and_matches_exactly(mocker):
    mocker.patch.object(options, "simulation_mode", False)
    mocker.patch.object(options, "opt_compat_check", True)
    mocker.patch.object(options, "main_window", FakeMainWindow())
    version = b"SYS_RENAULT_CMF-B_LL_DEV_SW0645" + b" " + b"\x00" * 3   # > 16 bytes, padded
    responses = {
        "22F1A0": _frame("62F1A0", [0x05]),
        "22F18A": _frame("62F18A", b"VALEO" + b" " * 10 + b"\x00\x00"),
        "22F194": _frame("62F194", b"USA1_0645" + b" " * 5 + b"\x00"),
        "22F195": _frame("62F195", version),
    }
    transport = FakeTransport(responses)
    mocker.patch.object(options, "elm", transport)

    target = EcuIdent("5", "VALEO", "USA1_0645", "SYS_RENAULT_CMF-B_LL_DEV_SW0645",
                      "USA_CMFB_V_3_1", "SONAR", "usa.json", "CAN", ["X95"], "0E")
    scanner = make_scanner([target])
    assert scanner.identify_new("0E", None) is True
    assert len(scanner.ecus) == 1                      # exact match, no fallback
    assert scanner.pending_compatibility is None
    assert transport.cmds == ["1001"]


def test_check_ecu2_logs_not_found_line_when_approximate_not_retained(mocker):
    mocker.patch.object(options, "simulation_mode", False)
    mocker.patch.object(options, "opt_compat_check", True)
    window = FakeMainWindow()
    mocker.patch.object(options, "main_window", window)
    mocker.patch.object(options, "elm", FakeTransport({}))
    mocker.patch.object(ecu_compatibility, "_default_loader", lambda href: make_ecu_file())

    # same soft, version delta far above 0xFFFFFF: approximate accepted but nothing kept
    targets = [ident("ACU_V5", "acu5.json", soft="BL06.42", version="0620190820")]
    scanner = make_scanner(targets)
    scanner.check_ecu2("14", "213", "BL06.42", "0642190820", None, "58", "CAN")

    assert scanner.approximate_ecus == {}
    assert scanner.pending_compatibility is not None
    lines = window.logview.lines
    # Messages are translated (French UI), so check the colors used by check_ecu2
    assert len(lines) == 2
    assert "color='red'" in lines[0]        # "no relevant ECU file found"
    assert "color='orange'" in lines[1]     # "Compatibility check ... probing"
