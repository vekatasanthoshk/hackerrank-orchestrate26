"""SQLite snapshot exports -> Observations.

Every ``.sql`` file is executed in an in-memory SQLite database. Each row of each
data table becomes one Observation tagged with the table name, so a record that
only survives in a reporting / regional / failover replica is still visible as
its own copy (replication drift). JSON payload columns (``record_json``) are
flattened before interpretation.
"""
import json
import re
import sqlite3

from .common import flatten, interpret, make_obs, system_for

TABLE_SYSTEM = {
    "customer_profiles": "account_service",
    "customer_search_documents": "search_service",
    "search_documents_primary": "search_service",
    "customer_analytics_profiles": "analytics_platform",
    "support_records": "support_platform",
    "customer_exports": "export_service",
    "connector_subscriptions": "integration_service",
    "backup_restore_entries": "backup_service",
    "security_audit_records": "security_service",
}


def parse_sql(path, file_id, captured_at):
    text = open(path, encoding="utf-8").read()
    m = re.search(r"Captured at:\s*(\S+)", text)
    header_ts = m.group(1) if m else captured_at
    con = sqlite3.connect(":memory:")
    con.executescript(text)
    con.row_factory = sqlite3.Row
    tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
    scope = {}
    if "snapshot_scope" in tables:
        scope = {r["origin_system"]: r["captured_at"] for r in con.execute("select * from snapshot_scope")}
    out = []
    for table in tables:
        if table == "snapshot_scope":
            continue
        for row in con.execute(f'select * from "{table}"'):
            rec = dict(row)
            if "record_json" in rec:
                payload = json.loads(rec.pop("record_json"))
                rec.update(flatten(payload))
            rid = rec.get("resource_id")
            if not rid:
                continue
            system = rec.get("origin_system") or TABLE_SYSTEM.get(table) or system_for(rid)
            for k in ("enabled", "restore_allowed"):
                if k in rec and rec[k] in (0, 1, "0", "1"):
                    rec[k] = "true" if str(rec[k]) == "1" else "false"
            exists, exposed, active, cat = interpret(system, rec)
            observed = rec.get("updated_at") or rec.get("indexed_at") or scope.get(system) or header_ts
            obs = make_obs(file_id, captured_at, observed, rid, exists, rec, system_id=system,
                           category=cat, exposed=exposed, active=active,
                           replica=table, source=f"sql:{table}")
            if rec.get("source_resource_id"):  # search documents point at their source account
                obs.links.add(rec["source_resource_id"])
            out.append(obs)
    con.close()
    return out
