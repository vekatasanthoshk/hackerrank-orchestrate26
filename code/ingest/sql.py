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


# Evidence SQL is untrusted input that we *execute*. The authorizer limits it to
# building and reading in-memory tables: no ATTACH (which would create files on
# disk), no PRAGMA other than harmless ones, no extension loading, no triggers or views.
_ALLOWED_PRAGMAS = {"foreign_keys", "table_info"}
_DENY = {sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH, sqlite3.SQLITE_CREATE_TRIGGER,
         sqlite3.SQLITE_CREATE_TEMP_TRIGGER, sqlite3.SQLITE_CREATE_VIEW, sqlite3.SQLITE_CREATE_TEMP_VIEW,
         sqlite3.SQLITE_CREATE_VTABLE, sqlite3.SQLITE_ALTER_TABLE}


def _authorizer(action, arg1, arg2, dbname, source):
    if action in _DENY:
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_PRAGMA and (arg1 or "").lower() not in _ALLOWED_PRAGMAS:
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION and (arg2 or "").lower() in ("load_extension", "readfile", "writefile"):
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def _quote_ident(name):
    return '"' + str(name).replace('"', '""') + '"'


def parse_sql(path, file_id, captured_at):
    with open(path, encoding="utf-8-sig") as fh:
        text = fh.read()
    m = re.search(r"Captured at:\s*(\S+)", text)
    header_ts = m.group(1) if m else captured_at
    con = sqlite3.connect(":memory:")
    try:
        return _read_snapshot(con, text, header_ts, file_id, captured_at)
    finally:
        con.close()


def _read_snapshot(con, text, header_ts, file_id, captured_at):
    con.set_authorizer(_authorizer)
    if hasattr(con, "enable_load_extension"):
        con.enable_load_extension(False)
    con.executescript(text)
    con.set_authorizer(None)
    con.row_factory = sqlite3.Row
    tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
    scope = {}
    if "snapshot_scope" in tables:
        scope = {r["origin_system"]: r["captured_at"] for r in con.execute("select * from snapshot_scope")}
    out = []
    for table in tables:
        if table == "snapshot_scope":
            continue
        for row in con.execute(f"select * from {_quote_ident(table)}"):
            rec = dict(row)
            if "record_json" in rec:
                try:
                    payload = json.loads(rec.pop("record_json") or "{}")
                except ValueError:
                    payload = {}
                if isinstance(payload, dict):
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
    return out
