# Protocols:
# KWP2000 FastInit MonoPoint            ?ATSP 5?
# KWP2000 FastInit MultiPoint           ?ATSP 5?
# KWP2000 Init 5 Baud Type I and II     ?ATSP 4?
# DiagOnCAN                             ATSP 6
# CAN Messaging (125 kbps CAN)          ?ATSP B?
# ISO8                                  ?ATSP 3?

# Identity sentinels. All identity fields are strings; diagversion is a
# decimal string ("14", "144"), never re-interpreted as hexadecimal.
NO_IDENT = ""                 # no identity at all (ecu.zip entry without autoidents): never matched
PLACEHOLDER_DIAGVERSION = "0"  # XML target without AutoIdent
PLACEHOLDER_SUPPLIER = "??????"
PLACEHOLDER_SOFT = "0000"
PLACEHOLDER_VERSION = "0000"


def clean_ident(value):
    """Single normalization point for identity strings: drop NUL padding and outer blanks."""
    if value is None:
        return NO_IDENT
    return str(value).replace("\x00", "").strip()


def clean_diagversion(value):
    """Diagnostic version as canonical decimal string ("04" -> "4")."""
    v = clean_ident(value)
    return str(int(v)) if v.isdigit() else v


class EcuIdent:
    def __init__(self, diagversion, supplier, soft, version, name, group, href, protocol, projects, address,
                 zipped=False):
        self.diagversion = clean_diagversion(diagversion)
        self.supplier = clean_ident(supplier)
        self.soft = clean_ident(soft)
        self.version = clean_ident(version)
        self.name = name
        self.group = group
        self.projects = projects
        self.href = href
        self.addr = address
        if "CAN" in protocol.upper():
            self.protocol = 'CAN'
        elif "KWP" in protocol.upper():
            self.protocol = 'KWP2000'
        elif "ISO8" in protocol.upper():
            self.protocol = 'ISO8'
        elif "DOIP" in protocol.upper():
            self.protocol = 'DOIP'
        else:
            self.protocol = 'UNKNOWN'
        self.hash = self.diagversion + self.supplier + self.soft + self.version
        self.zipped = zipped

    def checkWith(self, diagversion, supplier, soft, version, addr):
        if self.diagversion == NO_IDENT:
            return
        supplier_strip = self.supplier.strip()
        soft_strip = self.soft.strip()
        version_strip = self.version.strip()
        if self.diagversion != diagversion:
            return False
        if supplier_strip != supplier.strip()[:len(supplier_strip)]:
            return False
        if soft_strip != soft.strip()[:len(soft_strip)]:
            return False
        if version_strip != version.strip()[:len(version_strip)]:
            return False

        self.addr = addr
        return True

    # Minimal checking
    def checkApproximate(self, diagversion, supplier, soft, addr):
        if self.diagversion == NO_IDENT:
            return
        if self.supplier.strip() != supplier.strip():
            return False
        if self.soft.strip() != soft.strip():
            return False

        self.addr = addr
        return True

    def checkInGroup(self, diagversion, supplier, addr, project):
        """Third identification level: same functional group (address), same
        supplier and same diagnostic version inside the selected project.
        Strict equality, no prefix matching; soft and version do not filter."""
        if self.diagversion == NO_IDENT:
            return False
        if self.protocol != 'CAN':
            return False
        if str(self.addr).upper() != str(addr).upper():
            return False
        if self.supplier != supplier:
            return False
        if self.diagversion != diagversion:
            return False
        if not project:
            return False
        # vehiclemap is built with upper-cased project codes (EcuDatabase.addVehicleMapEntry);
        # EcuIdent.projects keeps the raw names, so compare the same way.
        return str(project).upper() in {str(p).upper() for p in self.projects}

    def dump(self):
        js = {}
        js['diagnostic_version'] = self.diagversion
        js['supplier_code'] = self.supplier
        js['soft_version'] = self.soft
        js['version'] = self.version
        js['group'] = self.group
        js['projects'] = [p for p in self.projects]
        js['protocol'] = self.protocol
        js['address'] = self.addr
        return js
