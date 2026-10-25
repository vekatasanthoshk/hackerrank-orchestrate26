"""Load every evidence file listed in evidence_files.csv into one Observation table.

Evidence is treated as untrusted input:
  * a manifest path must resolve inside ``dataset/evidence/`` (no ``..`` / absolute
    paths / symlinks pointing elsewhere), and the file_id must be a plain token;
  * files above MAX_BYTES are skipped;
  * a corrupt or unreadable file is skipped with a warning instead of aborting the
    whole run, so one bad artifact cannot take down the other 517 answers.
Warnings are collected in ``WARNINGS`` and printed to stderr by main.py.
"""
import csv
import os
import re

from .common import SAFE_ID_RE, ts_norm
from .json_records import parse_json
from .logs import log_observations
from .media import media_observations
from .sql import parse_sql
from .text import parse_text

MAX_BYTES = 50 * 1024 * 1024
WARNINGS = []


def warn(msg):
    WARNINGS.append(msg)


def load_manifest(dataset):
    with open(os.path.join(dataset, "evidence_files.csv"), encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def safe_evidence_path(dataset, rel_path):
    """Absolute path of a manifest entry, or None when it escapes dataset/evidence/."""
    if not rel_path or os.path.isabs(rel_path):
        return None
    root = os.path.realpath(os.path.join(dataset, "evidence"))
    full = os.path.realpath(os.path.join(dataset, rel_path))
    if os.path.commonpath([root, full]) != root:
        return None
    return full


def load_observations(dataset):
    obs = []
    seen = set()
    for row in load_manifest(dataset):
        fid = (row.get("file_id") or "").strip()
        cap = ts_norm((row.get("captured_at") or "").strip())
        if not SAFE_ID_RE.match(fid) or fid in seen:
            warn(f"skipped manifest row with invalid or duplicate file_id {fid!r}")
            continue
        seen.add(fid)
        path = safe_evidence_path(dataset, (row.get("file_path") or "").strip())
        if path is None:
            warn(f"{fid}: path {row.get('file_path')!r} is outside dataset/evidence; skipped")
            continue
        if not os.path.isfile(path):
            warn(f"{fid}: file not found {row.get('file_path')!r}; skipped")
            continue
        if os.path.getsize(path) > MAX_BYTES:
            warn(f"{fid}: larger than {MAX_BYTES} bytes; skipped")
            continue
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", cap or ""):
            warn(f"{fid}: unparseable captured_at {row.get('captured_at')!r}; skipped (cannot apply the audit cut-off)")
            continue
        ext = os.path.splitext(path)[1].lower()
        try:
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
            else:
                warn(f"{fid}: unsupported file type {ext!r}; skipped")
        except Exception as exc:  # isolate one corrupt artifact from the rest of the run
            warn(f"{fid}: could not be parsed ({type(exc).__name__}: {exc}); skipped")
    from . import media

    WARNINGS.extend(media.ERRORS)
    media.ERRORS.clear()
    return obs


LINK_RE = re.compile(r"linked (\S+) \(([^)]+)\) to (\S+) and (user_\d+)")
ATTACH_RE = re.compile(r"confirmed (\S+) \(([^)]+)\) belongs only to (\S+) and (user_\d+)")


def load_activity(dataset):
    """system_activity.csv rows plus data-catalog identity links extracted from them.

    Activity rows are *claims* (reported_result is not proof of state). The only
    facts taken from them are explicit catalog links of the form
    "Data catalog linked <resource> (<alias>) to <email> and <user_id>".
    """
    with open(os.path.join(dataset, "system_activity.csv"), encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
    links = []
    for r in rows:
        if r.get("event_type") != "LINK_RESOURCE_IDENTITY" or r.get("reported_result") != "SUCCESS":
            continue
        m = LINK_RE.search(r.get("details") or "") or ATTACH_RE.search(r.get("details") or "")
        if m:
            rid, alias, email, uid = m.groups()
            links.append({"activity_id": r["activity_id"], "event_time": ts_norm(r["event_time"]),
                          "system_id": r["target_system"], "resource_id": rid, "alias": alias,
                          "email": email.rstrip(";,."), "user_id": uid})
    return rows, links
