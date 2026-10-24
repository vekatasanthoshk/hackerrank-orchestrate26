"""Identity resolution: current + historical identifiers per user, normalised for matching.

Sources: user_identities.csv (current snapshot) and user_audit_log.csv (every
historical email / phone / email_hash value). Email hashes are
sha256(lower(email)), so a hash is also derived for every historical email.

Matching is deliberately grounded: an evidence record belongs to a user only when
it carries one of that user's exact (normalised) emails, phones, email hashes or
their stable ``user_NN`` reference. Names are never used to link records because
the dataset contains near-identical decoy names and emails.
"""
import csv
import hashlib
import os
import re

USER_RE = re.compile(r"^user_\d+$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def norm(value):
    """Normalise an identifier to its matching key, or None when it is not one."""
    if value is None:
        return None
    v = str(value).strip()
    if not v:
        return None
    low = v.lower()
    if USER_RE.match(low):
        return low
    if EMAIL_RE.match(low):
        return low
    if HASH_RE.match(low):
        return low
    digits = re.sub(r"\D", "", v)
    if len(digits) >= 8 and re.fullmatch(r"[+\d\s().\-]+", v):
        return "tel:" + digits
    return None


def email_hash(email):
    return hashlib.sha256(email.strip().lower().encode()).hexdigest()


class Identities:
    def __init__(self, dataset):
        self.users = {}
        with open(os.path.join(dataset, "user_identities.csv"), encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                self.users[r["user_id"]] = {
                    "user_id": r["user_id"], "name": r["name"],
                    "emails": {r["email"].strip().lower()}, "phones": {r["phone"]},
                    "hashes": {r["email_hash"].lower()}, "history": [],
                }
        with open(os.path.join(dataset, "user_audit_log.csv"), encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                u = self.users.get(r["user_id"])
                if not u:
                    continue
                u["history"].append(r)
                for v in (r["old_value"], r["new_value"]):
                    if r["field_name"] == "email":
                        u["emails"].add(v.strip().lower())
                    elif r["field_name"] == "phone":
                        u["phones"].add(v)
                    elif r["field_name"] == "email_hash":
                        u["hashes"].add(v.lower())
        self.index = {}
        for uid, u in self.users.items():
            for e in u["emails"]:
                u["hashes"].add(email_hash(e))
            keys = {uid.lower()} | u["emails"] | u["hashes"] | {norm(p) for p in u["phones"]}
            u["keys"] = {k for k in keys if k}
            for k in u["keys"]:
                self.index.setdefault(k, set()).add(uid)

    def users_for_email(self, email):
        return sorted(self.index.get((email or "").strip().lower(), set()))

    def keys(self, uid):
        return self.users[uid]["keys"]

    def owners(self, raw_idents):
        """Users referenced by any identifier in ``raw_idents``."""
        out = set()
        for raw in raw_idents:
            k = norm(raw)
            if k and k in self.index:
                out |= self.index[k]
        return out

    def describe(self, uid):
        u = self.users[uid]
        return {"user_id": uid, "name": u["name"], "emails": sorted(u["emails"]),
                "phones": sorted(u["phones"]), "hashes": len(u["hashes"]),
                "history": [(h["audit_id"], h["field_name"], h["event_time"]) for h in u["history"]]}
