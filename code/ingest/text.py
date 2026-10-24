"""Plain-text shift handover: ``- ts | system | resource | CATEGORY | STATE | identifier``."""
import re

from .common import interpret, make_obs

ROW_RE = re.compile(r"^-\s*(\S+)\s*\|\s*(\S+)\s*\|\s*(\S+)\s*\|\s*([A-Z_]+)\s*\|\s*([A-Z_]+)\s*\|\s*(.+?)\s*$")


def parse_text(path, file_id, captured_at):
    out = []
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        lines = fh.readlines()
    for line in lines:
        m = ROW_RE.match(line.strip())
        if not m:
            continue
        ts, system, rid, category, state, ident = m.groups()
        rec = {"result": state, "record_type": category, "subject_reference": ident}
        exists, exposed, active, cat = interpret(system, rec)
        out.append(make_obs(file_id, captured_at, ts, rid, exists, rec, system_id=system,
                            category=cat or category, exposed=exposed, active=active, source="text"))
    return out
