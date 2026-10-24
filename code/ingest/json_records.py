"""JSON evidence (snapshot bundles, service exports, manifests, reports) -> Observations.

All JSON shapes are handled by one recursive walk: any object that carries a
``resource_id`` is a record. Context such as the owning system
(``data_store`` / ``system`` / the ``service_exports`` key) and the most specific
timestamp (``observed_at`` > ``recorded_at`` > ``captured_at`` > ``exported_at``)
is inherited from enclosing objects.
"""
import json

from .common import flatten, interpret, make_obs, system_for, SYSTEM_CATEGORY

TIME_KEYS = ("observed_at", "recorded_at", "captured_at", "exported_at")


def _records(node, ctx):
    if isinstance(node, list):
        for x in node:
            yield from _records(x, ctx)
        return
    if not isinstance(node, dict):
        return
    ctx = dict(ctx)
    for k in TIME_KEYS:
        if isinstance(node.get(k), str):
            ctx["time"] = node[k]
            break
    if isinstance(node.get("data_store"), str):
        ctx["system"] = node["data_store"]
    if isinstance(node.get("system"), str):
        ctx["system"] = node["system"]
    if "resource_id" in node and isinstance(node["resource_id"], str):
        yield node, ctx
        return
    for k, v in node.items():
        if k == "service_exports" and isinstance(v, dict):
            for svc, colls in v.items():
                yield from _records(colls, dict(ctx, system=svc))
        elif isinstance(v, (dict, list)):
            yield from _records(v, ctx)


def parse_json(path, file_id, captured_at):
    data = json.load(open(path, encoding="utf-8"))
    out = []
    for node, ctx in _records(data, {"time": captured_at}):
        rec = dict(node)
        hits = rec.pop("hits", None)
        if isinstance(hits, dict):  # search query read-back
            docs = hits.get("documents") or []
            same = [d for d in docs if d.get("resource_id") == rec["resource_id"]] or docs[:1]
            if same:
                rec.update({k: v for k, v in same[0].items() if k != "resource_id"})
            rec["total_hits"] = str(hits.get("total", len(docs)))
            rec["result"] = "hit" if docs else "miss"
        nested_profile = "profile" in rec and rec["profile"] is None
        rec = flatten(rec)
        if nested_profile:
            rec["profile"] = None
        rid = rec["resource_id"]
        system = system_for(rid) or ctx.get("system")
        if ctx.get("system") in SYSTEM_CATEGORY and system_for(rid) is None:
            system = ctx["system"]
        exists, exposed, active, cat = interpret(system, rec)
        observed = rec.get("observed_at") or rec.get("recorded_at") or ctx.get("time") or captured_at
        out.append(make_obs(file_id, captured_at, observed, rid, exists, rec, system_id=system,
                            category=cat, exposed=exposed, active=active, source="json"))
    return out
