"""Third identification level: ``checkInGroup()`` and read-only compatibility probe.

Pure core module (no Qt). Flow:

    check_in_group()   -> candidates, href groups, signature groups   (no bus access)
    probe_report()     -> one read-only probe per signature group      (bus access via transport)

The transport is the active ELM/OBD object passed explicitly by the scanner.
"""

import hashlib
import json
import math
import re
from dataclasses import dataclass, field

import ddt4all.options as options
from ddt4all.core.ecu.ecu_file import EcuFile
from ddt4all.core.ecu.ecu_sessions import list_diag_sessions
from ddt4all.core.ecu.utils import hex16_tosigned, hex8_tosigned

# Safety guard only: every safe read of a definition is probed. The cap protects
# against aberrant definitions, it is not a sampling size.
MAX_COMPATIBILITY_PROBES = 200

# --- Request classification by service identifier -------------------------

CATEGORY_READ = "READ"
CATEGORY_WRITE = "WRITE"
CATEGORY_ROUTINE = "ROUTINE"
CATEGORY_CONTROL = "CONTROL"
CATEGORY_INFRASTRUCTURE = "INFRASTRUCTURE"
CATEGORY_OTHER = "OTHER"

SID_CATEGORIES = {
    CATEGORY_READ: ("21", "22", "1A", "19", "18", "17", "12"),
    CATEGORY_WRITE: ("2E", "3B", "3D", "34", "35", "36", "37", "14"),
    CATEGORY_ROUTINE: ("31",),
    CATEGORY_CONTROL: ("2F", "28", "85", "2C", "2A", "11"),
    CATEGORY_INFRASTRUCTURE: ("10", "3E", "27", "20", "83", "86", "87"),
}
SID_TO_CATEGORY = {sid: cat for cat, sids in SID_CATEGORIES.items() for sid in sids}

# Service 19 stays a READ for classification/signature purposes but is never
# probed: generic sub-functions and empty DTC lists give false failures.
NON_PROBED_READ_SIDS = ("19",)

# Number of identifier bytes echoed by the positive response, per read SID.
ECHO_LENGTH = {"22": 2, "21": 1, "1A": 1, "19": 1, "18": 0, "17": 0, "12": 0}

# Negative response codes that prove the definition does not match the ECU.
NRC_FAIL = {"11", "12", "31"}

# An enumerated list only rules an ECU out when it is selective: it must cover at
# most this share of the field's value domain (2 ** bitscount).
LIST_MAX_COVERAGE = 0.20

# Padding tolerated at the end of an ASCII field (NUL, space, erased flash).
_ASCII_PADDING = bytes((0x00, 0x20, 0xFF))

PROBE_PASS = "PASS"
PROBE_FAIL = "FAIL"
PROBE_INCONCLUSIVE = "INCONCLUSIVE"
PROBE_SKIPPED = "SKIPPED"

RESULT_PASS = "PASS"
RESULT_FAIL = "FAIL"
RESULT_NOT_TESTABLE = "NOT_TESTABLE"

_NRC_RE = re.compile(r'^(?:NR)?:([0-9A-F]{2}):')
_HEX_RE = re.compile(r'^[0-9A-F]+$')


# --- Structures -------------------------------------------------------------

@dataclass
class ScannedEcuIdentity:
    addr: str
    protocol: str
    diagversion: str
    supplier: str
    soft: str
    version: str
    project: str
    canline: int = 0


@dataclass
class DefinitionGroup:
    representative: object          # EcuIdent
    members: list                   # EcuIdent, representative included
    hrefs: list
    ecu_file: object                # EcuFile
    signature: str
    session_stream: str


@dataclass
class ProbeResult:
    request_name: str
    sentbytes: str
    response: str
    status: str                     # PROBE_*
    reason: str = ""


@dataclass
class CompatibilityResult:
    group: DefinitionGroup
    status: str                     # RESULT_*
    probes: list = field(default_factory=list)
    reason: str = ""

    @property
    def executed(self):
        return sum(1 for p in self.probes if p.status in (PROBE_PASS, PROBE_FAIL, PROBE_INCONCLUSIVE))

    @property
    def passed(self):
        return sum(1 for p in self.probes if p.status == PROBE_PASS)

    @property
    def failed(self):
        return sum(1 for p in self.probes if p.status == PROBE_FAIL)

    @property
    def inconclusive(self):
        return sum(1 for p in self.probes if p.status == PROBE_INCONCLUSIVE)

    @property
    def counts(self):
        """Compact ``pass/fail/inconclusive`` summary of the executed probes."""
        return "%d/%d/%d" % (self.passed, self.failed, self.inconclusive)


@dataclass
class CompatibilityReport:
    identity: ScannedEcuIdentity
    candidates: list = field(default_factory=list)   # EcuIdent before group by href
    groups: list = field(default_factory=list)       # DefinitionGroup
    results: list = field(default_factory=list)      # CompatibilityResult


# --- Logging ----------------------------------------------------------------

class CompatibilityLogger:
    """Writes into the existing low-level ELM log (transport.lf) when available."""

    def __init__(self, transport=None):
        self.lf = getattr(transport, "lf", 0) if transport is not None else 0

    def enabled(self):
        return bool(self.lf)

    def header(self, addr):
        if not self.lf:
            return
        try:
            self.lf.write('#' * 60 + "\n# Check compatibility: [SCAN] Addr: " + str(addr) + "\n" + '#' * 60 + "\n")
            self.lf.flush()
        except Exception:
            pass

    def line(self, text):
        if not self.lf:
            return
        try:
            self.lf.write("# " + str(text) + "\n")
        except Exception:
            pass

    def flush(self):
        if not self.lf:
            return
        try:
            self.lf.flush()
        except Exception:
            pass


# --- Classification ---------------------------------------------------------

def normalize_sentbytes(sentbytes):
    """Return the request bytes as an upper-case hex string, or '' if unusable."""
    if not sentbytes:
        return ""
    sb = str(sentbytes).replace(" ", "").upper()
    if len(sb) < 2 or len(sb) % 2 != 0 or not _HEX_RE.match(sb):
        return ""
    return sb


def classify_request(request):
    sb = normalize_sentbytes(getattr(request, "sentbytes", ""))
    if not sb:
        return CATEGORY_OTHER
    return SID_TO_CATEGORY.get(sb[:2], CATEGORY_OTHER)


def probe_skip_reason(request, ecu_file):
    """Return None when the request can be probed, else the reason it is skipped."""
    if classify_request(request) != CATEGORY_READ:
        return "not a read request"
    if normalize_sentbytes(request.sentbytes)[:2] in NON_PROBED_READ_SIDS:
        return "service %s not probed" % normalize_sentbytes(request.sentbytes)[:2]
    if not all(request.sds.values()):
        return "deny_sds restriction"
    if len(request.sendbyte_dataitems) > 0:
        return "dynamic request (send data items)"
    for name in request.dataitems.keys():
        if name not in ecu_file.data:
            return "definition incomplete (data %s missing)" % name
    return None


# --- Candidates and groups --------------------------------------------------

def find_group_candidates(targets, identity):
    return [t for t in targets
            if t.checkInGroup(identity.diagversion, identity.supplier, identity.addr, identity.project)]


def _default_loader(href):
    return EcuFile(options.ecus_dir + href, isfile=True)


def _dataitem_signature(name, di):
    return [name, int(di.firstbyte), int(di.bitoffset), str(di.endian), bool(di.ref)]


def _data_signature(data):
    return {
        "bitscount": data.bitscount,
        "bytescount": data.bytescount,
        "signed": bool(data.signed),
        "scaled": bool(data.scaled),
        "step": data.step,
        "offset": data.offset,
        "divideby": data.divideby,
        "byte": bool(data.byte),
        "binary": bool(data.binary),
        "bytesascii": bool(data.bytesascii),
        "lists": sorted([[int(k), str(v)] for k, v in data.lists.items()]),
        "items": sorted([[str(k), int(v)] for k, v in data.items.items()]),
    }


def compute_signature(ecu_file, session_stream):
    """Canonical functional signature (sorted JSON + SHA-256) of a definition."""
    requests = []
    referenced = set()
    infra_sessions = []
    for request in ecu_file.requests.values():
        category = classify_request(request)
        sb = normalize_sentbytes(request.sentbytes)
        if category == CATEGORY_INFRASTRUCTURE and sb.startswith("10"):
            infra_sessions.append(sb)
        if category not in (CATEGORY_READ, CATEGORY_WRITE, CATEGORY_ROUTINE, CATEGORY_CONTROL):
            continue
        receive = sorted(_dataitem_signature(n, d) for n, d in request.dataitems.items())
        send = sorted(_dataitem_signature(n, d) for n, d in request.sendbyte_dataitems.items())
        referenced.update(request.dataitems.keys())
        referenced.update(request.sendbyte_dataitems.keys())
        requests.append({
            "category": category,
            "sentbytes": sb,
            "minbytes": int(request.minbytes or 0),
            "shiftbytescount": int(request.shiftbytescount or 0),
            "sds": {k: bool(v) for k, v in request.sds.items()},
            "receive": receive,
            "send": send,
        })
    requests.sort(key=lambda r: json.dumps(r, sort_keys=True))

    data = {}
    for name in sorted(referenced):
        if name in ecu_file.data:
            data[name] = _data_signature(ecu_file.data[name])

    payload = {
        "session": session_stream,
        "sessions": sorted(set(infra_sessions)),
        "endian": ecu_file.endianness,
        "requests": requests,
        "data": data,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_definition_groups(candidates, ecu_file_loader=None, logger=None):
    """Group candidates by href (one EcuFile load each), then merge identical signatures."""
    loader = ecu_file_loader or _default_loader
    logger = logger or CompatibilityLogger()

    by_href = {}
    for target in candidates:
        by_href.setdefault(target.href, []).append(target)

    by_signature = {}
    for href in sorted(by_href.keys()):
        members = by_href[href]
        try:
            ecu_file = loader(href)
        except Exception as e:
            logger.line("Href %s: load error %s" % (href, e))
            continue
        if ecu_file is None or not getattr(ecu_file, "requests", None):
            logger.line("Href %s: no usable definition, skipped" % href)
            continue
        try:
            _, session_stream = list_diag_sessions(ecu_file)
            signature = compute_signature(ecu_file, session_stream)
        except Exception as e:
            logger.line("Href %s: signature error %s" % (href, e))
            continue
        logger.line("Href group %s: %s" % (href, ", ".join(sorted({t.name for t in members}))))

        if signature in by_signature:
            group = by_signature[signature]
            group.members.extend(members)
            group.hrefs.append(href)
        else:
            by_signature[signature] = DefinitionGroup(
                representative=None, members=list(members), hrefs=[href],
                ecu_file=ecu_file, signature=signature, session_stream=session_stream)

    groups = []
    for group in by_signature.values():
        group.members.sort(key=lambda t: (t.name, t.href))
        group.representative = group.members[0]
        groups.append(group)
    groups.sort(key=lambda g: (g.representative.name, g.representative.href))
    return groups


def check_in_group(identity, targets, ecu_file_loader=None, logger=None):
    """Compute candidates and definition groups for an unidentified ECU. No bus access."""
    logger = logger or CompatibilityLogger()
    report = CompatibilityReport(identity=identity)

    logger.header(identity.addr)
    logger.line("Project: %s / CAN line: %s" % (identity.project, identity.canline))
    logger.line("Identity: Supplier %s / Diag %s / Soft %s / Version %s"
                % (identity.supplier, identity.diagversion, identity.soft, identity.version))
    logger.flush()

    report.candidates = find_group_candidates(targets, identity)
    logger.line("Candidates before group by href: %d" % len(report.candidates))
    for t in report.candidates:
        logger.line("  %s (%s) soft %s version %s" % (t.name, t.href, t.soft, t.version))
    if not report.candidates:
        logger.flush()
        return report

    report.groups = build_definition_groups(report.candidates, ecu_file_loader, logger)
    logger.line("Signature groups: %d" % len(report.groups))
    for i, g in enumerate(report.groups):
        others = [m.name for m in g.members[1:]]
        logger.line("  Group %d: representative %s [%s]%s"
                    % (i + 1, g.representative.name, g.session_stream,
                       (" + " + ", ".join(others)) if others else ""))
    logger.flush()
    return report


# --- Probe ------------------------------------------------------------------

def probe_priority(request, ecu_file):
    """Sort key ranking how much a read can tell about the definition: requests with
    content checks (ASCII or selective list) first, most checkable items first, then
    requests with data items (exact length only), then requests without data items."""
    content = 0
    for name, dataitem in request.dataitems.items():
        data = ecu_file.data.get(name)
        if data is not None and (data.bytesascii or list_check_applies(data, dataitem, request)):
            content += 1
    if content:
        return 0, -content
    return (1 if request.dataitems else 2), 0


def select_probe_requests(ecu_file, max_probes=MAX_COMPATIBILITY_PROBES):
    """Return ``(selected, skipped)``: the safe reads by decreasing probe priority
    (then sentbytes), unique by sentbytes and capped by the safety guard, and the
    skipped READ requests with their reason."""
    selected = []
    skipped = []
    seen = set()
    reads = [r for r in ecu_file.requests.values() if classify_request(r) == CATEGORY_READ]
    reads.sort(key=lambda r: (probe_priority(r, ecu_file), normalize_sentbytes(r.sentbytes), r.name))
    for request in reads:
        reason = probe_skip_reason(request, ecu_file)
        if reason is not None:
            skipped.append((request, reason))
            continue
        sb = normalize_sentbytes(request.sentbytes)
        if sb in seen:
            continue
        seen.add(sb)
        if len(selected) < max_probes:
            selected.append(request)
    return selected, skipped


def parse_response(raw):
    """Classify a transport.request() result: ('error'|'silence'|'nrc'|'data', payload)."""
    text = "" if raw is None else str(raw).strip().upper()
    if "WRONG" in text or "ERROR" in text:
        return "error", text
    if not text:
        return "silence", ""
    m = _NRC_RE.match(text)
    if m:
        return "nrc", m.group(1)
    tokens = text.split()
    if not tokens or not all(len(t) == 2 and _HEX_RE.match(t) for t in tokens):
        return "error", text
    return "data", tokens


def item_last_byte(data, dataitem):
    """1-based index of the last response byte covered by a data item (0 if unusable)."""
    if dataitem.firstbyte < 1:
        return 0
    return dataitem.firstbyte + int(math.ceil((data.bitscount + dataitem.bitoffset) / 8.0)) - 1


def expected_response_length(request, ecu_file):
    """Exact length of a fixed-size response: the declared minbytes, or the last byte
    covered by a data item when that goes further. 0 when it cannot be derived."""
    last = 0
    for name, dataitem in request.dataitems.items():
        data = ecu_file.data.get(name)
        if data is None:
            return 0
        item_last = item_last_byte(data, dataitem)
        if not item_last:
            return 0
        last = max(last, item_last)
    if not last:
        return 0
    return max(last, int(request.minbytes or 0))


def list_check_applies(data, dataitem, request):
    """True when a value outside ``data.lists`` proves a definition mismatch: the list
    is selective (partial domain, low coverage) and the field is always returned
    (entirely inside the guaranteed ``minbytes`` part of the response)."""
    if data.scaled or data.bytesascii or not data.lists:
        return False
    domain = 2 ** data.bitscount
    if len(data.lists) >= domain or len(data.lists) / domain > LIST_MAX_COVERAGE:
        return False
    return 0 < item_last_byte(data, dataitem) <= int(request.minbytes or 0)


def value_in_list(data, hexval):
    """Same value interpretation as EcuData.getDisplayValue for non scaled items."""
    val = int(hexval, 16)
    if data.signed:
        if data.bytescount == 1:
            val = hex8_tosigned(val)
        elif data.bytescount == 2:
            val = hex16_tosigned(val)
    return val in data.lists


def is_printable_ascii(hexval):
    """Printable ASCII, tolerating trailing padding (an erased or blank field passes)."""
    raw = bytes.fromhex(hexval).rstrip(_ASCII_PADDING)
    return all(0x20 <= b <= 0x7E for b in raw)


def validate_positive(request, data_bytes, ecu_file):
    """Structural and content validation of a positive response. Returns (status, reason)."""
    sb = normalize_sentbytes(request.sentbytes)
    sid = sb[:2]
    expected = "%02X" % (int(sid, 16) + 0x40)
    if not data_bytes or data_bytes[0] != expected:
        return PROBE_FAIL, "unexpected positive SID %s (expected %s)" % (data_bytes[0] if data_bytes else "", expected)

    echo_len = ECHO_LENGTH.get(sid, 0)
    if echo_len:
        expected_echo = sb[2:2 + 2 * echo_len]
        got = "".join(data_bytes[1:1 + echo_len])
        if len(data_bytes) < 1 + echo_len or got != expected_echo:
            return PROBE_FAIL, "identifier echo mismatch (%s != %s)" % (got, expected_echo)

    if request.minbytes and len(data_bytes) < int(request.minbytes):
        return PROBE_FAIL, "response length %d < minbytes %d" % (len(data_bytes), int(request.minbytes))

    expected_len = expected_response_length(request, ecu_file)
    if expected_len and len(data_bytes) != expected_len:
        return PROBE_FAIL, "response length %d != expected %d" % (len(data_bytes), expected_len)

    stream = " ".join(data_bytes)
    for name, dataitem in request.dataitems.items():
        data = ecu_file.data.get(name)
        if data is None:
            return PROBE_FAIL, "data %s missing" % name
        try:
            value = data.getDisplayValue(stream, dataitem, ecu_file.endianness)
        except Exception as e:
            return PROBE_FAIL, "data item %s decode error: %s" % (name, e)
        if value is None:
            return PROBE_FAIL, "data item %s not extractable" % name

        if data.bytesascii:
            if not is_printable_ascii(data.getHexValue(stream, dataitem, ecu_file.endianness)):
                return PROBE_FAIL, "data item %s is not printable ASCII" % name
        elif list_check_applies(data, dataitem, request):
            hexval = data.getHexValue(stream, dataitem, ecu_file.endianness)
            if not value_in_list(data, hexval):
                return PROBE_FAIL, "data item %s value %s not in list" % (name, hexval)
    return PROBE_PASS, "ok"


def close_probe_session(transport, session_stream):
    """Return the ECU to its default session, same convention as identify_new/identify_old."""
    close_cmd = '1001' if str(session_stream).upper().startswith("100") else '1081'
    try:
        transport.cmd(close_cmd)
    except Exception:
        pass
    try:
        transport.startSession = ""
    except Exception:
        pass


def group_verdict(n_pass, n_fail, n_executed):
    """PASS as soon as one read succeeded (the group stays selectable, ranked by its
    PASS count), FAIL when reads failed and none succeeded, otherwise NOT_TESTABLE."""
    if n_pass:
        return RESULT_PASS, ("%d of %d probes failed" % (n_fail, n_executed)) if n_fail else ""
    if n_fail:
        return RESULT_FAIL, "%d of %d probes failed, none passed" % (n_fail, n_executed)
    return RESULT_NOT_TESTABLE, "no conclusive read"


def probe_group(group, transport, logger=None):
    logger = logger or CompatibilityLogger()
    probes = []
    try:
        selected, skipped = select_probe_requests(group.ecu_file)
    except Exception as e:
        logger.line("Group %s: probe selection error %s" % (group.representative.name, e))
        logger.flush()
        return CompatibilityResult(group, RESULT_NOT_TESTABLE, [], "probe selection error")

    for request, reason in skipped:
        probes.append(ProbeResult(request.name, normalize_sentbytes(request.sentbytes), "", PROBE_SKIPPED, reason))

    logger.line("Group %s: %d safe read(s), %d skipped read(s)"
                % (group.representative.name, len(selected), len(skipped)))
    for p in probes:
        logger.line("  %s [%s] %s -> SKIPPED: %s" % (p.request_name, p.sentbytes[:2], p.sentbytes, p.reason))

    if not selected:
        result = CompatibilityResult(group, RESULT_NOT_TESTABLE, probes, "no safe read request")
        logger.line("Group result: %s (%s) %s" % (result.status, result.counts, result.reason))
        logger.flush()
        return result

    try:
        accepted = bool(transport.start_session_can(group.session_stream))
    except Exception as e:
        logger.line("Session: %s -> exception %s" % (group.session_stream, e))
        accepted = False
    logger.line("Session: %s -> %s" % (group.session_stream, "accepted" if accepted else "refused"))
    if not accepted:
        result = CompatibilityResult(group, RESULT_NOT_TESTABLE, probes, "session refused")
        logger.line("Group result: %s (%s) %s" % (result.status, result.counts, result.reason))
        logger.flush()
        return result

    try:
        for request in selected:
            sb = normalize_sentbytes(request.sentbytes)
            try:
                raw = transport.request(sb, positive='', cache=False)
            except Exception as e:
                raw = ""
                status, reason = PROBE_INCONCLUSIVE, "transport exception: %s" % e
            else:
                kind, payload = parse_response(raw)
                if kind == "error":
                    status, reason = PROBE_FAIL, "transport error: %s" % payload
                elif kind == "silence":
                    status, reason = PROBE_INCONCLUSIVE, "no response"
                elif kind == "nrc":
                    if payload in NRC_FAIL:
                        status, reason = PROBE_FAIL, "NRC %s" % payload
                    else:
                        status, reason = PROBE_INCONCLUSIVE, "NRC %s" % payload
                else:
                    status, reason = validate_positive(request, payload, group.ecu_file)
            probe = ProbeResult(request.name, sb, "" if raw is None else str(raw).strip(), status, reason)
            probes.append(probe)
            logger.line("  %s [%s] %s -> %s -> %s: %s"
                        % (probe.request_name, sb[:2], sb, probe.response, probe.status, probe.reason))
    finally:
        close_probe_session(transport, group.session_stream)

    n_pass = sum(1 for p in probes if p.status == PROBE_PASS)
    n_fail = sum(1 for p in probes if p.status == PROBE_FAIL)
    n_exec = sum(1 for p in probes if p.status in (PROBE_PASS, PROBE_FAIL, PROBE_INCONCLUSIVE))
    status, reason = group_verdict(n_pass, n_fail, n_exec)
    result = CompatibilityResult(group, status, probes, reason)
    logger.line("Group result: %s (%s) %s" % (result.status, result.counts, result.reason))
    logger.flush()
    return result


def probe_report(report, transport, logger=None):
    """Probe every group of a report on the already configured CAN connection."""
    logger = logger or CompatibilityLogger(transport)
    report.results = []
    for group in report.groups:
        try:
            result = probe_group(group, transport, logger)
        except Exception as e:
            logger.line("Group %s: unexpected error %s" % (group.representative.name, e))
            logger.flush()
            result = CompatibilityResult(group, RESULT_NOT_TESTABLE, [], "error: %s" % e)
        report.results.append(result)
    # Rank groups by PASS count, best first; ties keep the deterministic name order
    report.results.sort(key=lambda r: (-r.passed, r.group.representative.name, r.group.representative.href))
    return report
