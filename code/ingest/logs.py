"""Parse every log dialect in dataset/evidence/logs into flat event dicts.

Supported line shapes (all start with an ISO timestamp):
  * logfmt            ``ts level=INFO service=x trace_id=t event=e k=v k="v"``
  * bracketed         ``ts [INFO] [service] [trace] event: k="v" ...``
  * pipe-delimited    ``ts | INFO | service | trace | event | k="v" ...``
  * JSON payload      ``ts {"severity": ..., "service": ..., ...}``
  * cloud runtime     ``ts requestId=t level=.. function=service message="k=\\"v\\" ..."``
  * RFC5424 syslog    ``ts <15>1 node service trace - - k="v" ...``

Each line becomes ``{"ts", "service", "trace", "event", **kv}``. Lines are then
grouped by trace id so that a ``*_started`` line carrying the lookup key and the
``*_completed`` line carrying the resource state are merged into one record.
"""
import json
import re

TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+(.*)$")
NOISE_EVENTS = {"cache_lookup", "connection_acquired", "dependency_retry", "dependency_recovered"}
KV_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=("(?:[^"\\]|\\.)*"|\S+)')


def _kv(text):
    out = {}
    for k, v in KV_RE.findall(text):
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1].replace('\\"', '"')
        out[k] = v
    return out


def parse_line(line):
    m = TS_RE.match(line.strip())
    if not m:
        return None
    ts, rest = m.groups()
    rec = {"ts": ts}
    if rest.startswith("{"):
        try:
            payload = json.loads(rest)
        except ValueError:
            return None
        rec.update({k: str(v) if v is not None else None for k, v in payload.items()})
        rec.setdefault("trace", payload.get("trace_id"))
        return rec
    if rest.startswith("["):
        parts = re.match(r"\[(\w+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+([A-Za-z0-9_]+):\s*(.*)$", rest)
        if not parts:
            return None
        level, service, trace, event, tail = parts.groups()
        rec.update(level=level, service=service, trace=trace, event=event)
        rec.update(_kv(tail))
        return rec
    if rest.startswith("|"):
        cols = [c.strip() for c in rest.strip("| ").split("|", 4)]
        if len(cols) < 5:
            return None
        rec.update(level=cols[0], service=cols[1], trace=cols[2], event=cols[3])
        rec.update(_kv(cols[4]))
        return rec
    if rest.startswith("<"):
        parts = re.match(r"<\d+>\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+-\s+-\s+(.*)$", rest)
        if not parts:
            return None
        _node, service, trace, tail = parts.groups()
        rec.update(service=service, trace=trace)
        rec.update(_kv(tail))
        return rec
    kv = _kv(rest)
    if "message" in kv and "function" in kv:  # cloud runtime export
        inner = _kv(kv.pop("message"))
        rec.update(service=kv.get("function"), trace=kv.get("requestId"), level=kv.get("level"))
        rec.update(inner)
        return rec
    rec.update(kv)
    rec["trace"] = kv.get("trace_id") or kv.get("seq")
    return rec


def parse_log(path):
    """Return a list of merged trace records (dicts) for one log file."""
    lines = []
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        for raw in fh:
            rec = parse_line(raw)
            if rec:
                lines.append(rec)
    traces, order = {}, []
    for i, rec in enumerate(lines):
        # Standalone rows (no trace id) or explicit record_lookup rows are their own record.
        key = rec.get("trace") if rec.get("trace") and rec.get("event") != "record_lookup" else f"line{i}"
        if key not in traces:
            traces[key] = {"lines": []}
            order.append(key)
        traces[key]["lines"].append(rec)
    merged = []
    for key in order:
        group = traces[key]["lines"]
        m = {"trace": key, "events": [g.get("event") for g in group]}
        for g in group:
            if g.get("event") in NOISE_EVENTS:
                continue  # infrastructure chatter (cache misses, retries) carries no record state
            for k, v in g.items():
                if k == "event":
                    continue
                if k not in m or v not in (None, "", "null"):
                    m[k] = v
        m["ts"] = group[-1]["ts"]
        merged.append(m)
    return merged


def log_observations(path, file_id, captured_at):
    """Merged trace records -> Observations (only traces that name a resource)."""
    from .common import RESOURCE_RE, interpret, make_obs, system_for

    out = []
    for m in parse_log(path):
        rid = m.get("resource_id")
        if not rid or not RESOURCE_RE.match(rid):
            continue
        system = m.get("system") if str(m.get("system", "")).endswith(("_service", "_platform")) else None
        system = system or system_for(rid)
        rec = dict(m)
        exists, exposed, active, cat = interpret(system, rec)
        out.append(make_obs(file_id, captured_at, m.get("ts"), rid, exists, rec, system_id=system,
                            category=cat, exposed=exposed, active=active, source="log"))
    return out
