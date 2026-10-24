"""Load every evidence file listed in evidence_files.csv into one Observation table."""
import csv
import os
import re

from .json_records import parse_json
from .logs import log_observations
from .media import media_observations
from .sql import parse_sql
from .text import parse_text


def load_manifest(dataset):
    with open(os.path.join(dataset, "evidence_files.csv"), encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def load_observations(dataset):
    obs = []
    for row in load_manifest(dataset):
        path = os.path.join(dataset, row["file_path"])
        fid, cap = row["file_id"], row["captured_at"]
        ext = os.path.splitext(path)[1].lower()
        if ext == ".sql":
            obs += parse_sql(path, fid, cap)
        elif ext == ".json":
            obs += parse_json(path, fid, cap)
        elif ext == ".log":
            obs += log_observations(path, fid, cap)
        elif ext == ".txt":
            obs += parse_text(path, fid, cap)
        elif ext in (".png", ".pdf", ".jpg", ".jpeg"):
            obs += media_observations(path, fid, row.get("origin", ""), cap)
    return obs


LINK_RE = re.compile(r"linked (\S+) \(([^)]+)\) to (\S+) and (user_\d+)")
ATTACH_RE = re.compile(r"confirmed (\S+) \(([^)]+)\) belongs only to (\S+) and (user_\d+)")


def load_activity(dataset):
    """system_activity.csv rows plus data-catalog identity links extracted from them.

    Activity rows are *claims* (reported_result is not proof of state). The only
    facts taken from them are explicit catalog links of the form
    "Data catalog linked <resource> (<alias>) to <email> and <user_id>".
    """
    with open(os.path.join(dataset, "system_activity.csv"), encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    links = []
    for r in rows:
        if r["event_type"] != "LINK_RESOURCE_IDENTITY" or r["reported_result"] != "SUCCESS":
            continue
        m = LINK_RE.search(r["details"]) or ATTACH_RE.search(r["details"])
        if m:
            rid, alias, email, uid = m.groups()
            links.append({"activity_id": r["activity_id"], "event_time": r["event_time"],
                          "system_id": r["target_system"], "resource_id": rid, "alias": alias,
                          "email": email.rstrip(";,."), "user_id": uid})
    return rows, links
