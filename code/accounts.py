"""Fallback linkage for primary accounts that no evidence ties to an identifier.

A deleted primary profile often reads back as a bare ``404`` with no email, so
the account id cannot be linked through identifiers. The deletion workflow
does leave one grounded trace: just before a batch of requests is reported
(``reported_at``), the deletion worker submits each request's primary profile
(``DELETE_RECORD`` on account_service).

For each reporting batch (requests sharing ``reported_at``) we take the account
submissions in the 3 hours before the report that no evidence links to any user.
We assign one only when exactly one request in the batch still lacks a
grounded account and exactly one such submission exists. Within larger batches
the submission order does not follow any request attribute we could verify on
the samples, so those stay unassigned rather than guessed. The inferred
account only adds a verification check (or uses a 404 read-back of that id).
It never creates a finding by itself.
"""
from collections import defaultdict
from datetime import datetime, timedelta

from ingest.common import ts_norm

WINDOW = timedelta(hours=3)


def _t(s):
    """Parse a timestamp in any ISO form; None when it cannot be parsed."""
    try:
        return datetime.strptime(ts_norm(s or ""), "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def infer_batch_accounts(requests, activity, index, identities):
    owned_anywhere = {o.resource_id for o in index.obs if o.resource_id and index.owner_cache[id(o)]}
    owned_anywhere |= {l["resource_id"] for l in index.links}
    submissions = [a for a in activity if a["event_type"] == "DELETE_RECORD"
                   and a["target_system"] == "account_service" and a["source_system"] == "deletion_worker"
                   and a["resource_id"] not in owned_anywhere]
    batches = defaultdict(list)
    for r in requests:
        batches[r["reported_at"]].append(r)
    out = {}
    for reported_at, reqs in batches.items():
        need = []
        for r in reqs:
            users = identities.users_for_email(r["email"])
            has = any(rid.startswith("account_") for u in users
                      for rid in index.owned_resources(u, r["audit_at"]))
            if not has:
                need.append(r)
        if not need:
            continue
        rep = _t(reported_at)
        if rep is None:
            continue
        cands = sorted((a for a in submissions
                        if _t(a["event_time"]) is not None and timedelta(0) <= rep - _t(a["event_time"]) <= WINDOW),
                       key=lambda a: a["event_time"])
        cands = list(dict.fromkeys(a["resource_id"] for a in cands))
        if len(need) == 1 and len(cands) == 1:
            out[need[0]["case_id"]] = cands[0]
    return out
