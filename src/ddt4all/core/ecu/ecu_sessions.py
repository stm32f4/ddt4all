"""Diagnostic session discovery shared by ParamWidget and the compatibility probe.

Pure helper, no Qt: reproduces the session list that ParamWidget builds for
its session combo and the default session DDT4ALL would select for a definition.
"""

DEFAULT_SESSION_LABEL = "After sales (default) [10C0]"
DEFAULT_SESSION_STREAM = "10C0"


def list_diag_sessions(ecu_file):
    """Return ``(sessions, default_stream)``.

    ``sessions`` is an ordered list of ``(label, stream)`` starting with the
    After Sales entry, followed by every ``Start*Diag*Session`` request of the
    definition (one entry per session name when the request carries a
    "Session Name" data item). ``default_stream`` is the first entry whose
    label contains ``EXTENDED``, otherwise ``10C0``.
    """
    sessions = [(DEFAULT_SESSION_LABEL, DEFAULT_SESSION_STREAM)]

    for reqname, request in ecu_file.requests.items():
        uppername = reqname.upper()
        if "START" not in uppername or "DIAG" not in uppername or "SESSION" not in uppername:
            continue

        sessionnamefound = False
        for di in request.sendbyte_dataitems.keys():
            dataitemnameupper = di.upper()
            if "SESSION" not in dataitemnameupper or "NAME" not in dataitemnameupper:
                continue
            ecu_data = ecu_file.data.get(di)
            if ecu_data is None:
                continue
            for dataname in ecu_data.items.keys():
                try:
                    stream = "".join(request.build_data_stream({di: dataname}))
                except Exception:
                    continue
                sessions.append((dataname + " [" + stream + "]", stream))
                sessionnamefound = True

        if len(request.sendbyte_dataitems) == 0 or not sessionnamefound:
            try:
                stream = "".join(request.build_data_stream({}))
            except Exception:
                continue
            sessions.append((reqname + " [" + stream + "]", stream))

    default_stream = DEFAULT_SESSION_STREAM
    for label, stream in sessions:
        if "EXTENDED" in label.upper():
            default_stream = stream
            break

    return sessions, default_stream
