import io

from ddt4all.core.ecu.ecu_compatibility import (
    CATEGORY_CONTROL,
    CATEGORY_INFRASTRUCTURE,
    CATEGORY_OTHER,
    CATEGORY_READ,
    CATEGORY_ROUTINE,
    CATEGORY_WRITE,
    MAX_COMPATIBILITY_PROBES,
    PROBE_FAIL,
    PROBE_INCONCLUSIVE,
    PROBE_PASS,
    PROBE_SKIPPED,
    CompatibilityReport,
    RESULT_FAIL,
    RESULT_NOT_TESTABLE,
    RESULT_PASS,
    CompatibilityLogger,
    ScannedEcuIdentity,
    build_definition_groups,
    check_in_group,
    classify_request,
    compute_signature,
    list_check_applies,
    parse_response,
    probe_group,
    probe_report,
    select_probe_requests,
    validate_positive,
)
from ddt4all.core.ecu.ecu_data import EcuData
from ddt4all.core.ecu.ecu_file import EcuFile
from ddt4all.core.ecu.ecu_ident import EcuIdent
from ddt4all.core.ecu.ecu_request import EcuRequest


# --- helpers ----------------------------------------------------------------

def make_ecu_file(requests, data=None, endian=""):
    ecu = EcuFile(None)
    ecu.endianness = endian
    for name, value in (data or {}).items():
        ecu.data[name] = EcuData(value, name)
    for req in requests:
        r = EcuRequest(req, ecu)
        ecu.requests[r.name] = r
    return ecu


BASE_DATA = {
    "A": {"bitscount": 8, "bytescount": 1},
    "B": {"bitscount": 16, "bytescount": 2, "scaled": True, "step": 0.5},
}

BASE_REQUESTS = [
    {"name": "ReadA", "sentbytes": "22F190", "minbytes": 4, "replybytes": "62F19000",
     "receivebyte_dataitems": {"A": {"firstbyte": 4}}, "deny_sds": []},
    {"name": "ReadB", "sentbytes": "2101", "minbytes": 4,
     "receivebyte_dataitems": {"B": {"firstbyte": 3}}, "deny_sds": []},
    {"name": "ReadDenied", "sentbytes": "22F191", "deny_sds": ["supplier"]},
    {"name": "ReadDynamic", "sentbytes": "22F192", "sendbyte_dataitems": {"A": {"firstbyte": 4}}},
    {"name": "WriteA", "sentbytes": "2EF190", "sendbyte_dataitems": {"A": {"firstbyte": 4}}},
    {"name": "RoutineX", "sentbytes": "3101FF00"},
    {"name": "IoControl", "sentbytes": "2FF19003"},
    {"name": "ReadMemory", "sentbytes": "2300001000"},
    {"name": "StartDiagnosticSession.Extended", "sentbytes": "1003"},
]


def make_ident(name="ECU_A", href="ecu_a.json", diagversion="14", supplier="213",
               soft="00A5", version="8300", addr="58", projects=("X95",), protocol="CAN"):
    return EcuIdent(diagversion, supplier, soft, version, name, "GRP", href, protocol, list(projects), addr)


def make_group(ecu_file, session="10C0", name="ECU_A"):
    from ddt4all.core.ecu.ecu_compatibility import DefinitionGroup
    rep = make_ident(name=name)
    return DefinitionGroup(representative=rep, members=[rep], hrefs=[rep.href],
                           ecu_file=ecu_file, signature="sig", session_stream=session)


class FakeTransport:
    def __init__(self, responses=None, session_ok=True):
        self.responses = responses or {}
        self.session_ok = session_ok
        self.requests = []          # (req, positive, cache)
        self.sessions = []
        self.cmds = []
        self.startSession = "XX"
        self.lf = 0

    def start_session_can(self, stream):
        self.sessions.append(stream)
        self.startSession = stream
        return self.session_ok

    def request(self, req, positive='', cache=True):
        self.requests.append((req, positive, cache))
        return self.responses.get(req, "")

    def cmd(self, command, serviceDelay="0"):
        self.cmds.append(command)
        return ""


# --- classification ---------------------------------------------------------

def test_classify_request_by_sid():
    ecu = make_ecu_file(BASE_REQUESTS, BASE_DATA)
    assert classify_request(ecu.requests["ReadA"]) == CATEGORY_READ
    assert classify_request(ecu.requests["ReadB"]) == CATEGORY_READ
    assert classify_request(ecu.requests["WriteA"]) == CATEGORY_WRITE
    assert classify_request(ecu.requests["RoutineX"]) == CATEGORY_ROUTINE
    assert classify_request(ecu.requests["IoControl"]) == CATEGORY_CONTROL
    assert classify_request(ecu.requests["ReadMemory"]) == CATEGORY_OTHER
    assert classify_request(ecu.requests["StartDiagnosticSession.Extended"]) == CATEGORY_INFRASTRUCTURE
    assert classify_request(EcuRequest({"name": "NoBytes"}, ecu)) == CATEGORY_OTHER
    assert classify_request(EcuRequest({"name": "Odd", "sentbytes": "221"}, ecu)) == CATEGORY_OTHER
    assert classify_request(EcuRequest({"name": "NotHex", "sentbytes": "22ZZ"}, ecu)) == CATEGORY_OTHER


def test_select_probe_requests_only_safe_static_reads():
    ecu = make_ecu_file(BASE_REQUESTS, BASE_DATA)
    selected, skipped = select_probe_requests(ecu)
    assert [r.name for r in selected] == ["ReadB", "ReadA"]       # sorted by sentbytes
    reasons = {r.name: reason for r, reason in skipped}
    assert "deny_sds" in reasons["ReadDenied"]
    assert "dynamic" in reasons["ReadDynamic"]
    assert "WriteA" not in reasons and "RoutineX" not in reasons


def test_select_probe_requests_dedupes_and_caps():
    reqs = [{"name": "R%03d" % i, "sentbytes": "22%04X" % i} for i in range(MAX_COMPATIBILITY_PROBES + 5)]
    reqs.append({"name": "Duplicate", "sentbytes": "220000"})
    ecu = make_ecu_file(reqs)
    selected, _ = select_probe_requests(ecu)
    assert len(selected) == MAX_COMPATIBILITY_PROBES
    assert len({r.sentbytes for r in selected}) == MAX_COMPATIBILITY_PROBES


PRIORITY_DATA = {
    "S": {"bitscount": 24, "byte": True, "bytescount": 3, "bytesascii": True},
    "L": {"lists": {"0": "a", "1": "b"}},
    "N": {"bitscount": 8},
}

PRIORITY_REQUESTS = [
    {"name": "ReadNone", "sentbytes": "220001"},
    {"name": "ReadPlain", "sentbytes": "220002", "minbytes": 4,
     "receivebyte_dataitems": {"N": {"firstbyte": 4}}},
    {"name": "ReadList", "sentbytes": "220003", "minbytes": 4,
     "receivebyte_dataitems": {"L": {"firstbyte": 4}}},
    {"name": "ReadTwoChecks", "sentbytes": "220004", "minbytes": 7,
     "receivebyte_dataitems": {"S": {"firstbyte": 4}, "L": {"firstbyte": 7}}},
]


def test_select_probe_requests_prioritizes_reads_that_carry_content_checks():
    ecu = make_ecu_file(PRIORITY_REQUESTS, PRIORITY_DATA)
    selected, _ = select_probe_requests(ecu)
    assert [r.name for r in selected] == ["ReadTwoChecks", "ReadList", "ReadPlain", "ReadNone"]


def test_select_probe_requests_cap_keeps_the_highest_priority_reads():
    ecu = make_ecu_file(PRIORITY_REQUESTS, PRIORITY_DATA)
    selected, _ = select_probe_requests(ecu, max_probes=2)
    assert [r.name for r in selected] == ["ReadTwoChecks", "ReadList"]


def test_service_19_is_never_probed():
    ecu = make_ecu_file([{"name": "ReportDTC", "sentbytes": "1902FF"},
                         {"name": "ReadA", "sentbytes": "22F190"}])
    selected, skipped = select_probe_requests(ecu)
    assert [r.name for r in selected] == ["ReadA"]
    assert skipped[0][0].name == "ReportDTC" and "not probed" in skipped[0][1]


def test_missing_data_definition_is_skipped():
    ecu = make_ecu_file([{"name": "ReadX", "sentbytes": "2201",
                          "receivebyte_dataitems": {"Missing": {"firstbyte": 3}}}])
    _, skipped = select_probe_requests(ecu)
    assert "definition incomplete" in skipped[0][1]


# --- response parsing -------------------------------------------------------

def test_parse_response_contract():
    assert parse_response("62 F1 90 05") == ("data", ["62", "F1", "90", "05"])
    assert parse_response("") == ("silence", "")
    assert parse_response("   ") == ("silence", "")
    assert parse_response(":31:NR: Request Out Of Range") == ("nrc", "31")
    assert parse_response("NR:7F:NR: Service Not Supported In Active Session") == ("nrc", "7F")
    assert parse_response("WRONG RESPONSE")[0] == "error"
    assert parse_response("ODD ERROR")[0] == "error"
    assert parse_response("garbage")[0] == "error"


# --- signature and grouping -------------------------------------------------

def test_signature_ignores_cosmetic_differences():
    a = make_ecu_file(BASE_REQUESTS, BASE_DATA)
    cosmetic = [dict(r) for r in BASE_REQUESTS]
    cosmetic[0] = dict(cosmetic[0], manualsend=True, replybytes="62F190FF")
    data = {k: dict(v) for k, v in BASE_DATA.items()}
    data["A"]["comment"] = "other comment"
    data["A"]["unit"] = "km"
    b = make_ecu_file(list(reversed(cosmetic)), data)
    assert compute_signature(a, "1003") == compute_signature(b, "1003")


def test_signature_changes_on_functional_differences():
    base = make_ecu_file(BASE_REQUESTS, BASE_DATA)
    ref = compute_signature(base, "1003")

    variants = []
    r = [dict(x) for x in BASE_REQUESTS]; r[0] = dict(r[0], sentbytes="22F19A"); variants.append((r, BASE_DATA))
    r = [dict(x) for x in BASE_REQUESTS]; r[0] = dict(r[0], minbytes=5); variants.append((r, BASE_DATA))
    r = [dict(x) for x in BASE_REQUESTS]; r[0] = dict(r[0], receivebyte_dataitems={"A": {"firstbyte": 5}}); variants.append((r, BASE_DATA))
    r = [dict(x) for x in BASE_REQUESTS]; r[0] = dict(r[0], deny_sds=["plant"]); variants.append((r, BASE_DATA))
    d = {k: dict(v) for k, v in BASE_DATA.items()}; d["A"]["signed"] = True; variants.append((BASE_REQUESTS, d))

    for reqs, data in variants:
        assert compute_signature(make_ecu_file(reqs, data), "1003") != ref
    assert compute_signature(base, "10C0") != ref


def test_build_definition_groups_loads_each_href_once_and_merges_identical():
    loads = []

    def loader(href):
        loads.append(href)
        return make_ecu_file(BASE_REQUESTS, BASE_DATA)

    candidates = [
        make_ident(name="MFD v5.4", href="mfd54.json", soft="1111"),
        make_ident(name="MFD v5.4", href="mfd54.json", soft="2222"),   # same href, other autoident
        make_ident(name="MFD v5.2", href="mfd52.json"),
        make_ident(name="MFD v5.3", href="mfd53.json"),
    ]
    groups = build_definition_groups(candidates, ecu_file_loader=loader)
    assert sorted(loads) == ["mfd52.json", "mfd53.json", "mfd54.json"]
    assert len(groups) == 1
    group = groups[0]
    assert group.representative.name == "MFD v5.2"
    assert [m.name for m in group.members] == ["MFD v5.2", "MFD v5.3", "MFD v5.4", "MFD v5.4"]
    assert group.session_stream == "1003"


def test_build_definition_groups_separates_different_definitions_and_skips_unreadable():
    def loader(href):
        if href == "broken.json":
            raise IOError("cannot read")
        if href == "empty.json":
            return EcuFile(None)
        reqs = [dict(x) for x in BASE_REQUESTS]
        if href == "b.json":
            reqs[0] = dict(reqs[0], minbytes=9)
        return make_ecu_file(reqs, BASE_DATA)

    candidates = [make_ident(name="A", href="a.json"), make_ident(name="B", href="b.json"),
                  make_ident(name="C", href="broken.json"), make_ident(name="D", href="empty.json")]
    groups = build_definition_groups(candidates, ecu_file_loader=loader)
    assert [g.representative.name for g in groups] == ["A", "B"]


def test_check_in_group_filters_targets_and_logs_header():
    identity = ScannedEcuIdentity("58", "CAN", "14", "213", "243C", "2931", "X95", 0)
    targets = [
        make_ident(name="Same", href="same.json", soft="ZZZZ", version="0000"),
        make_ident(name="OtherAddr", href="o1.json", addr="26"),
        make_ident(name="OtherSupplier", href="o2.json", supplier="214"),
        make_ident(name="OtherDiag", href="o3.json", diagversion="15"),
        make_ident(name="OtherProject", href="o4.json", projects=["X61"]),
        make_ident(name="Kwp", href="o5.json", protocol="KWP2000"),
    ]
    log = io.StringIO()
    transport = FakeTransport()
    transport.lf = log
    report = check_in_group(identity, targets, ecu_file_loader=lambda h: make_ecu_file(BASE_REQUESTS, BASE_DATA),
                            logger=CompatibilityLogger(transport))
    assert [t.name for t in report.candidates] == ["Same"]
    assert len(report.groups) == 1
    text = log.getvalue()
    assert "# Check compatibility: [SCAN] Addr: 58" in text
    assert "Project: X95" in text


# --- probe ------------------------------------------------------------------

def test_probe_group_pass_sends_only_safe_reads_without_cache():
    ecu = make_ecu_file(BASE_REQUESTS, BASE_DATA)
    transport = FakeTransport({"22F190": "62 F1 90 05", "2101": "61 01 00 10"})
    result = probe_group(make_group(ecu, session="1003"), transport)

    assert result.status == RESULT_PASS
    assert result.passed == 2 and result.executed == 2
    assert result.counts == "2/0/0"
    sent = [r[0] for r in transport.requests]
    assert sent == ["2101", "22F190"]
    assert all(cache is False for _, _, cache in transport.requests)
    assert not any(s[:2] in ("2E", "31", "2F", "23", "3B", "11", "14", "27") for s in sent)
    assert transport.sessions == ["1003"]
    assert transport.cmds == ["1001"]
    assert transport.startSession == ""
    skipped = {p.request_name: p for p in result.probes if p.status == PROBE_SKIPPED}
    assert set(skipped) == {"ReadDenied", "ReadDynamic"}


def test_probe_group_closes_non_uds_session_with_1081():
    ecu = make_ecu_file(BASE_REQUESTS, BASE_DATA)
    transport = FakeTransport({"22F190": "62 F1 90 05", "2101": "61 01 00 10"})
    probe_group(make_group(ecu, session="10C0"), transport)
    assert transport.cmds == ["1081"]


def test_probe_group_nrc_31_counts_as_fail_and_verdict_is_by_proportion():
    ecu = make_ecu_file(BASE_REQUESTS, BASE_DATA)
    # 1 FAIL out of 2 executed: not more than half -> PASS
    transport = FakeTransport({"22F190": ":31:NR: Request Out Of Range", "2101": "61 01 00 10"})
    result = probe_group(make_group(ecu), transport)
    statuses = {p.request_name: p.status for p in result.probes}
    assert statuses["ReadA"] == PROBE_FAIL and statuses["ReadB"] == PROBE_PASS
    assert result.status == RESULT_PASS
    # 2 FAIL out of 2 executed -> FAIL
    transport = FakeTransport({"22F190": ":31:NR: Request Out Of Range", "2101": ":11:NR: Service Not Supported"})
    result = probe_group(make_group(ecu), transport)
    assert result.status == RESULT_FAIL


def test_group_verdict_rules():
    from ddt4all.core.ecu.ecu_compatibility import group_verdict
    assert group_verdict(8, 2, 10)[0] == RESULT_PASS
    assert group_verdict(1, 9, 10)[0] == RESULT_PASS         # one PASS keeps the group selectable
    assert group_verdict(0, 6, 10)[0] == RESULT_FAIL
    assert group_verdict(0, 0, 3)[0] == RESULT_NOT_TESTABLE  # only inconclusive probes
    assert group_verdict(0, 0, 0)[0] == RESULT_NOT_TESTABLE
    assert group_verdict(1, 0, 1)[0] == RESULT_PASS


def test_probe_report_ranks_groups_by_pass_count():
    from ddt4all.core.ecu.ecu_compatibility import DefinitionGroup
    full = make_ecu_file(BASE_REQUESTS, BASE_DATA)
    partial = make_ecu_file([r for r in BASE_REQUESTS if r["name"] != "ReadB"], BASE_DATA)
    identity = ScannedEcuIdentity("58", "CAN", "14", "213", "243C", "2931", "X95", 0)
    report = CompatibilityReport(identity=identity)
    for name, ecu in (("A_partial", partial), ("B_full", full)):
        rep = make_ident(name=name, href=name + ".json")
        report.groups.append(DefinitionGroup(representative=rep, members=[rep], hrefs=[rep.href],
                                             ecu_file=ecu, signature=name, session_stream="10C0"))
    transport = FakeTransport({"22F190": "62 F1 90 05", "2101": "61 01 00 10"})
    probe_report(report, transport)
    assert [(r.group.representative.name, r.passed) for r in report.results] == [("B_full", 2), ("A_partial", 1)]


def test_probe_group_silence_and_session_nrc_are_inconclusive():
    ecu = make_ecu_file(BASE_REQUESTS, BASE_DATA)
    transport = FakeTransport({"22F190": "", "2101": ":7F:NR: Service Not Supported In Active Session"})
    result = probe_group(make_group(ecu), transport)
    assert result.status == RESULT_NOT_TESTABLE
    assert {p.status for p in result.probes if p.request_name in ("ReadA", "ReadB")} == {PROBE_INCONCLUSIVE}
    assert result.executed == 2 and result.passed == 0
    assert (result.passed, result.failed, result.inconclusive) == (0, 0, 2)
    assert result.counts == "0/0/2"


def test_result_counts_split_pass_fail_inconclusive():
    ecu = make_ecu_file(BASE_REQUESTS, BASE_DATA)
    transport = FakeTransport({"22F190": ":31:NR: Request Out Of Range", "2101": ""})
    result = probe_group(make_group(ecu), transport)
    assert result.counts == "0/1/1"


def test_probe_group_structural_failures():
    ecu = make_ecu_file(BASE_REQUESTS, BASE_DATA)
    # wrong echo, and a response too short for minbytes / data item
    transport = FakeTransport({"22F190": "62 F1 91 05", "2101": "61 01 00"})
    result = probe_group(make_group(ecu), transport)
    assert result.status == RESULT_FAIL
    reasons = {p.request_name: p.reason for p in result.probes}
    assert "echo" in reasons["ReadA"]
    assert "minbytes" in reasons["ReadB"]
    # wrong positive SID on both reads
    transport = FakeTransport({"22F190": "7E 00", "2101": "7E 00"})
    result = probe_group(make_group(ecu), transport)
    assert result.status == RESULT_FAIL
    assert all(p.status == PROBE_FAIL for p in result.probes if p.request_name in ("ReadA", "ReadB"))


# --- response content validation -------------------------------------------

def read_ecu(data, dataitems, minbytes, sent="22F190"):
    return make_ecu_file([{"name": "R", "sentbytes": sent, "minbytes": minbytes,
                           "receivebyte_dataitems": dataitems, "deny_sds": []}], data)


def check(ecu, response):
    return validate_positive(ecu.requests["R"], response.split(), ecu)


def test_validate_positive_requires_exact_response_length():
    ecu = read_ecu({"A": {"bitscount": 8}}, {"A": {"firstbyte": 4}}, 4)
    assert check(ecu, "62 F1 90 05")[0] == PROBE_PASS
    status, reason = check(ecu, "62 F1 90 05 06")
    assert status == PROBE_FAIL and "expected 4" in reason


def test_validate_positive_expected_length_uses_minbytes_when_larger_than_items():
    ecu = read_ecu({"A": {"bitscount": 1}}, {"A": {"firstbyte": 4}}, 5)
    assert check(ecu, "62 F1 90 05 00")[0] == PROBE_PASS
    assert check(ecu, "62 F1 90 05 00 00")[0] == PROBE_FAIL


def test_validate_positive_without_data_items_does_not_check_length():
    ecu = make_ecu_file([{"name": "R", "sentbytes": "22F190", "minbytes": 3}])
    assert check(ecu, "62 F1 90 01 02 03")[0] == PROBE_PASS


ASCII_DATA = {"S": {"bitscount": 24, "byte": True, "bytescount": 3, "bytesascii": True}}


def test_validate_positive_ascii_field_must_be_printable():
    ecu = read_ecu(ASCII_DATA, {"S": {"firstbyte": 4}}, 6)
    assert check(ecu, "62 F1 90 41 42 43")[0] == PROBE_PASS
    assert check(ecu, "62 F1 90 41 00 00")[0] == PROBE_PASS       # trailing padding
    assert check(ecu, "62 F1 90 FF FF FF")[0] == PROBE_PASS       # blank field
    status, reason = check(ecu, "62 F1 90 41 01 43")
    assert status == PROBE_FAIL and "ASCII" in reason
    assert check(ecu, "62 F1 90 41 00 43")[0] == PROBE_FAIL       # padding only counts at the end


def test_validate_positive_list_rejects_value_outside_a_selective_list():
    data = {"L": {"lists": {"0": "a", "1": "b", "2": "c"}}}
    ecu = read_ecu(data, {"L": {"firstbyte": 4}}, 4)
    assert check(ecu, "62 F1 90 01")[0] == PROBE_PASS
    status, reason = check(ecu, "62 F1 90 07")
    assert status == PROBE_FAIL and "not in list" in reason


def test_validate_positive_list_ignores_fields_beyond_minbytes():
    data = {"L": {"lists": {"0": "a", "1": "b", "2": "c"}}}
    ecu = read_ecu(data, {"L": {"firstbyte": 4}}, 3)              # optional tail: not guaranteed
    assert check(ecu, "62 F1 90 07")[0] == PROBE_PASS


def test_validate_positive_list_ignores_dense_lists():
    data = {"L": {"lists": {str(i): "v" for i in range(60)}}}      # 60/256 > 20 %
    ecu = read_ecu(data, {"L": {"firstbyte": 4}}, 4)
    assert check(ecu, "62 F1 90 70")[0] == PROBE_PASS


def test_validate_positive_list_on_bit_field_and_signed_value():
    nibble = read_ecu({"F": {"bitscount": 4, "lists": {"0": "a"}}}, {"F": {"firstbyte": 4}}, 4)
    assert check(nibble, "62 F1 90 0F")[0] == PROBE_PASS          # high nibble is 0
    assert check(nibble, "62 F1 90 50")[0] == PROBE_FAIL          # high nibble is 5

    signed = read_ecu({"N": {"signed": True, "lists": {"-1": "neg"}}}, {"N": {"firstbyte": 4}}, 4)
    assert check(signed, "62 F1 90 FF")[0] == PROBE_PASS
    assert check(signed, "62 F1 90 05")[0] == PROBE_FAIL


def test_list_check_applies_only_to_selective_partial_lists():
    def applies(data, minbytes=4):
        ecu = read_ecu({"L": data}, {"L": {"firstbyte": 4}}, minbytes)
        request = ecu.requests["R"]
        return list_check_applies(ecu.data["L"], request.dataitems["L"], request)

    assert applies({"lists": {"0": "a", "1": "b"}})
    assert not applies({"bitscount": 1, "lists": {"0": "a", "1": "b"}})            # complete domain
    assert not applies({"bitscount": 2, "lists": {str(i): "v" for i in range(4)}})
    assert not applies({"bitscount": 1, "lists": {"0": "a"}})                       # 50 % coverage
    assert not applies({"scaled": True, "lists": {"0": "a"}})
    assert not applies({"lists": {}})
    assert applies({"bitscount": 16, "bytescount": 2, "lists": {"1": "a", "2": "b"}}, minbytes=5)


def test_probe_group_reports_list_mismatch_as_probe_failure():
    data = {"L": {"lists": {"0": "a", "1": "b"}}}
    ecu = read_ecu(data, {"L": {"firstbyte": 4}}, 4)
    result = probe_group(make_group(ecu), FakeTransport({"22F190": "62 F1 90 09"}))
    probe = next(p for p in result.probes if p.request_name == "R")
    assert probe.status == PROBE_FAIL and "not in list" in probe.reason
    assert result.status == RESULT_FAIL


def test_probe_group_session_refused_sends_nothing():
    ecu = make_ecu_file(BASE_REQUESTS, BASE_DATA)
    transport = FakeTransport(session_ok=False)
    result = probe_group(make_group(ecu), transport)
    assert result.status == RESULT_NOT_TESTABLE
    assert result.reason == "session refused"
    assert transport.requests == []


def test_probe_group_without_safe_read_is_not_testable_without_session():
    ecu = make_ecu_file([r for r in BASE_REQUESTS if r["name"] not in ("ReadA", "ReadB")], BASE_DATA)
    transport = FakeTransport()
    result = probe_group(make_group(ecu), transport)
    assert result.status == RESULT_NOT_TESTABLE
    assert transport.sessions == [] and transport.requests == []


def test_probe_group_transport_exception_is_inconclusive():
    ecu = make_ecu_file(BASE_REQUESTS, BASE_DATA)

    class Broken(FakeTransport):
        def request(self, req, positive='', cache=True):
            raise OSError("adapter disconnected")

    transport = Broken()
    result = probe_group(make_group(ecu), transport)
    assert result.status == RESULT_NOT_TESTABLE
    assert transport.cmds == ["1081"]


def test_probe_report_probes_each_group_and_logs():
    ecu = make_ecu_file(BASE_REQUESTS, BASE_DATA)
    identity = ScannedEcuIdentity("58", "CAN", "14", "213", "243C", "2931", "X95", 0)
    report = check_in_group(identity, [make_ident(name="Same", href="s.json")],
                            ecu_file_loader=lambda h: ecu)
    log = io.StringIO()
    transport = FakeTransport({"22F190": "62 F1 90 05", "2101": "61 01 00 10"})
    transport.lf = log
    probe_report(report, transport, CompatibilityLogger(transport))
    assert [r.status for r in report.results] == [RESULT_PASS]
    text = log.getvalue()
    assert "Session: 1003 -> accepted" in text
    assert "Group result: PASS (2/0/0)" in text
