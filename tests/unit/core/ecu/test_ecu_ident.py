from ddt4all.core.ecu.ecu_ident import (
    NO_IDENT,
    EcuIdent,
    clean_diagversion,
    clean_ident,
)


def make_ident(diagversion="14", supplier="213", soft="00A5", version="8300",
               name="ECU_A", href="ecu_a.json", protocol="CAN", projects=("X95",), addr="58"):
    return EcuIdent(diagversion, supplier, soft, version, name, "GRP", href, protocol, list(projects), addr)


def test_clean_ident_removes_nul_and_padding():
    assert clean_ident("LGE       ") == "LGE"
    assert clean_ident("  BOSCH") == "BOSCH"
    assert clean_ident("00A5\x00\x00") == "00A5"
    assert clean_ident(None) == NO_IDENT


def test_clean_diagversion_is_canonical_decimal_string():
    assert clean_diagversion("04") == "4"
    assert clean_diagversion("14") == "14"
    assert clean_diagversion("144 ") == "144"
    assert clean_diagversion("") == NO_IDENT
    assert clean_diagversion("??") == "??"


def test_ecu_ident_normalizes_fields_once_at_construction():
    ident = make_ident(diagversion="04", supplier="LGE       ", soft="243C\x00", version=" 2931 ")
    assert ident.diagversion == "4"
    assert ident.supplier == "LGE"
    assert ident.soft == "243C"
    assert ident.version == "2931"
    assert ident.hash == "4LGE243C2931"


def test_checkwith_compares_decimal_strings():
    ident = make_ident(diagversion="14")
    # decimal "14" from the frame (0x0E) matches decimal "14" from the file
    assert ident.checkWith("14", "213", "00A5", "8300", "58") is True
    # hexadecimal re-interpretation is gone: "20" (0x14) does not match "14"
    assert ident.checkWith("20", "213", "00A5", "8300", "58") is False
    # leading zero canonicalized on the file side
    assert make_ident(diagversion="04").checkWith("4", "213", "00A5", "8300", "58") is True


def test_checkwith_keeps_prefix_matching_for_other_fields():
    ident = make_ident(soft="00A5", version="8300")
    assert ident.checkWith("14", "213", "00A5FFEE", "8300XYZ", "58") is True
    assert ident.checkWith("14", "21", "00A5", "8300", "58") is False


def test_no_ident_never_matches():
    ident = make_ident(diagversion="", supplier="", soft="", version="")
    assert not ident.checkWith("", "", "", "", "58")
    assert not ident.checkApproximate("", "", "", "58")
    assert ident.checkInGroup("", "", "58", "X95") is False


def test_check_in_group_accepts_same_group_supplier_diagversion_in_project():
    ident = make_ident(soft="ZZZZ", version="0001")
    assert ident.checkInGroup("14", "213", "58", "X95") is True


def test_check_in_group_rejections():
    assert make_ident(projects=["X61"]).checkInGroup("14", "213", "58", "X95") is False
    assert make_ident(addr="26").checkInGroup("14", "213", "58", "X95") is False
    assert make_ident(supplier="214").checkInGroup("14", "213", "58", "X95") is False
    assert make_ident(diagversion="15").checkInGroup("14", "213", "58", "X95") is False
    assert make_ident(protocol="KWP2000 FastInit").checkInGroup("14", "213", "58", "X95") is False
    assert make_ident().checkInGroup("14", "213", "58", None) is False


def test_check_in_group_supplier_is_strict_not_prefix():
    assert make_ident(supplier="21").checkInGroup("14", "213", "58", "X95") is False
    assert make_ident(supplier="213").checkInGroup("14", "21", "58", "X95") is False


def test_check_in_group_project_case_follows_vehiclemap_convention():
    assert make_ident(projects=["x95"]).checkInGroup("14", "213", "58", "X95") is True
    assert make_ident(projects=["X95"]).checkInGroup("14", "213", "58", "x95") is True
    assert make_ident(addr="58").checkInGroup("14", "213", "58", "X95") is True
