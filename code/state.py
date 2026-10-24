"""As-of(audit_at) state reconstruction for one data subject.

Steps
  1. Visibility: only evidence files whose manifest ``captured_at`` <= audit_at
     exist for this case (later evidence must not change the answer).
  2. Ownership: a resource belongs to the subject when a visible observation of
     it carries one of the subject's grounded identifiers (current or historical
     email, phone, email hash, user_NN), when a visible owned record points at it
     (search document -> source account), or when a data-catalog link in
     system_activity.csv ties it (or a visible alias of it) to the subject.
  3. Latest state: per (system_id, resource_id) take the most recent visible
     observation (observed_at, then captured_at). Several copies inside that
     same file (primary + replicas) are merged: any surviving copy keeps the
     record present / exposed / active.
Activity rows other than catalog links are claims and never set state.
"""
from collections import defaultdict


class ResourceState:
    __slots__ = ("system_id", "resource_id", "category", "exists", "exposed", "active",
                 "evidence_id", "observed_at", "history")

    def __init__(self, system_id, resource_id):
        self.system_id = system_id
        self.resource_id = resource_id
        self.history = []

    def __repr__(self):
        return (f"<{self.system_id}/{self.resource_id} {self.category} exists={self.exists} "
                f"exposed={self.exposed} active={self.active} ev={self.evidence_id}@{self.observed_at}>")


class EvidenceIndex:
    """Observation table indexed for per-case queries."""

    def __init__(self, observations, catalog_links, identities):
        self.obs = [o for o in observations if o.resource_id or o.aliases]
        self.ids = identities
        self.links = catalog_links
        self.by_resource = defaultdict(list)
        # Media records whose id is not printed (statement numbers, file names, user refs)
        # take the resource id of the data-catalog link that names that alias. Done once
        # here so the result never depends on which case happens to be audited first.
        alias_map = {l["alias"]: l for l in catalog_links}
        for o in self.obs:
            if not o.resource_id:
                hit = next((alias_map[a] for a in sorted(o.aliases) if a in alias_map), None)
                if hit:
                    o.resource_id, o.system_id = hit["resource_id"], hit["system_id"]
        for o in self.obs:
            if o.resource_id:
                self.by_resource[o.resource_id].append(o)
        # owner users per observation, computed once
        self.owner_cache = {id(o): self.ids.owners(o.idents) for o in self.obs}

    def owned_resources(self, uid, audit_at=None):
        """resource_id -> how it was linked to the subject.

        Ownership is an identity fact, not a state: a later read-back that prints the
        subject's user reference next to an audit record still tells us *which* record
        belongs to them. Linkage therefore uses every file; the state of each resource
        (and every cited evidence id) is taken only from files visible at audit_at.
        """
        owned = {}
        for l in self.links:
            if l["user_id"] == uid or uid in self.ids.owners([l["email"]]):
                owned.setdefault(l["resource_id"], f"catalog:{l['activity_id']}")
        for o in self.obs:
            if uid in self.owner_cache[id(o)] and o.resource_id:
                owned.setdefault(o.resource_id, f"ident:{o.file_id}")
        # records that point at another resource (search doc -> source account)
        for rid in list(owned):
            for o in self.by_resource.get(rid, []):
                for target in o.links:
                    owned.setdefault(target, f"link:{rid}")
        return owned

    def state(self, resource_id, audit_at):
        visible = [o for o in self.by_resource.get(resource_id, []) if o.captured_at <= audit_at]
        if not visible:
            return None
        latest = max(visible, key=lambda o: (o.observed_at, o.captured_at))
        # Copies of the record inside the same snapshot: every table of a SQL capture
        # (primary + replicas), or the same read-back instant in any other format. A later
        # read in the same log does not get overridden by an earlier one.
        same = [o for o in visible if o.file_id == latest.file_id
                and (o.source.startswith("sql") or o.observed_at == latest.observed_at)]
        rs = ResourceState(latest.system_id, resource_id)
        rs.category = _pick_category(visible)
        rs.exists = any(o.exists for o in same)
        exp = [o.exposed for o in same if o.exposed is not None and o.exists]
        rs.exposed = any(exp) if exp else None
        act = [o.active for o in same if o.active is not None]
        rs.active = any(act) if act else None
        rs.evidence_id = latest.file_id
        rs.observed_at = latest.observed_at
        rs.history = sorted(visible, key=lambda o: (o.observed_at, o.captured_at))
        return rs


def _pick_category(observations):
    """The most specific category any observation assigned to the resource."""
    cats = [o.category for o in observations if o.category and o.category != "UNKNOWN"]
    for special in ("SUPPORT_ATTACHMENT", "SECONDARY_IDENTIFIER"):
        if special in cats:
            return special
    return cats[-1] if cats else "UNKNOWN"
