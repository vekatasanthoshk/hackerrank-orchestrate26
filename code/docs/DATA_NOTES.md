# Data notes (Phase 1 reconnaissance)

What the participant-facing data looks like and the rules reverse-engineered from the
32 public samples. Every claim here was checked against the files; nothing comes from
organizer-only data.

## Inputs at a glance

| File | Rows | Notes |
|---|---|---|
| `deletion_requests.csv` | 518 | case_33 … case_550, numeric order; 5 languages + English |
| `sample_deletion_requests.csv` / `sample_output.csv` | 32 | 22 INCOMPLETE, 10 COMPLETE, 0 NOT_APPLICABLE |
| `user_identities.csv` | 850 | current email / phone / email_hash per `user_id` |
| `user_audit_log.csv` | 306 | 107 email, 107 email_hash, 92 phone changes (old → new) |
| `system_activity.csv` | 4,011 | claims: 721 FAILED, 376 PARTIAL; 12 `LINK_RESOURCE_IDENTITY`, 10 `CLASSIFY_REQUEST` |
| `deletion_rules.csv` | 15 | category → DELETE / REDACT / ANONYMIZE / RETAIN |
| `evidence_files.csv` | 94 | 24 SQL, 28 JSON, 26 logs, 1 TXT, 11 PNG, 4 PDF |

## Identity

* `email_hash = sha256(lower(email))` (holds for all 850 users); historical hashes are in the
  audit log and are also derivable from historical emails.
* Request emails can be historical (100 of 518) and appear in mixed case
  (`BCARVALHO6517@GMAIL.COM`). Every request email resolves to exactly one user; no normalised
  identifier is shared by two users.
* Phones appear in several formats (`+82 10 0616 2075`, `+55 41 90257-9346`); matched on digits.
* Records reference users by email, historical email, email hash (`correlation_key=<sha256>`),
  phone (PII-scan `matched_value`), or `user_NN` (`customer_reference`, `subject_reference`,
  `subject_ref`, `lookup_key=user_NN`). Names are not used: decoys share near-identical names
  and emails (`g.silva76@gmail.com` vs `g.silva76.jr@gmail.com`, `Jonas Berg` vs `Jonas Berglund`).

## Evidence formats → (timestamp, system, resource, category, state, identifier)

| Format | Shape | State signal |
|---|---|---|
| SQL inventory (`customer_data_inventory_*`) | typed tables + `snapshot_scope(origin_system, captured_at)` | row present; PII columns null/non-null; `enabled`, `restore_allowed` 0/1 |
| SQL replicas (`read/regional/reporting/failover`) | `customer_data_primary` + replica tables, `record_json` payloads | a row only in a replica = replication drift (record still exists) |
| `customer_search_primary` | `search_documents_primary(source_resource_id)` | links a search document to its source account |
| JSON snapshot bundles | `snapshots[].{captured_at, data_store, records[]}` | inner `captured_at` can be days older than the file |
| JSON service exports | `service_exports.<system>.<collection>[]` with `observed_at` | `status_code 404` / `profile: null`, search `hits.total` |
| JSON manifests / ledgers | `records[].{system, resource_id, record_type, result, subject_reference}` | `FOUND` / `NOT_FOUND` |
| Logs (5 dialects: logfmt, bracketed, pipe, JSON, syslog, cloud-runtime) | trace-grouped: `*_started` carries the lookup key, `*_completed` the state | `rows`, `http_status`, `result=hit/miss`, `enabled`, `restore_allowed`, `eligible/deletion_block`, `decision=deny`, PII-scan `matched_value`, `direct_identifiers` |
| Shift-handover TXT | `ts \| system \| resource \| CATEGORY \| STATE \| identifier` | explicit |
| PNG / PDF (15) | admin consoles, statements, registers | vision extraction → same record schema (`prompts/media_extraction.md`) |

Noise to ignore: cache misses, connection/dependency retries, DNS/vault chatter, webhook failures.
A `cache_lookup result=miss` inside a trace is not a record miss.

## Rules confirmed by the samples

1. **Citation = latest visible observation.** For each resource the cited `evidence_id` is the file
   holding its most recent observation whose manifest `captured_at <= audit_at`
   (case_15: `evidence_01` 09-15 over `evidence_14` 08-07; case_09: `evidence_93` 09-16 over
   `evidence_06` 09-18, which is after `audit_at`).
2. **activity_id / audit_id are never cited** in the samples; every evidence id is a `file_id`.
3. **Retained-record linkage.** Security audit records link by `subject_reference=user_NN`;
   tombstones by `subject_reference`; account ↔ search via `source_resource_id`; media artifacts
   without printed ids via `LINK_RESOURCE_IDENTITY` catalog rows (alias → resource → user).
4. **Verification scope.** Every relevant resource gets a check for its required final state,
   including already-compliant ones (case_11: `account_4248` VERIFY_ABSENT and
   `audit_record_9394` VERIFY_PRESENT without findings). INCOMPLETE remediation and verification
   use `""`; COMPLETE verification cites evidence.
5. **Ordering.** Phase → operation-table order → `system_id` → `resource_id`.
   Remediation: DISABLE_DATA_FLOW → BLOCK_RESTORE → DELETE → REDACT → ANONYMIZE.
6. **Category nuances.**
   * analytics records keyed only by an email hash (`contact_lookup`) are secondary-identifier
     copies → DELETE (case_12), while identifiable analytics profiles → ANONYMIZE (case_11).
   * support attachments (attachment scans, PDF files) → DELETE (case_07, case_13); support
     messages → REDACT; the legacy support replica contact index → DELETE (case_10).
   * free-text bodies (`message_text`) can still contain an email → exposed.
   * backups: `restore_allowed=true` → REPORT_RESTORE_RISK + BLOCK_RESTORE (rule 14 RETAIN).
   * data flows: `enabled=true` → REPORT_ACTIVE_DATA_FLOW + DISABLE_DATA_FLOW.
7. **Episode scoping.** A subject can have several requests (user_17: case_46 in March, case_17
   in August). Resources whose observations all fall inside an earlier closed request belong to
   that request (case_17 excludes `account_6523` and `tombstone_17`; case_07 excludes `object_19`).
8. **Ownership may come from files exported after audit_at** (case_23 `audit_record_4128` is only in
   the 09-17 bundle, observed 09-15): such resources get a check only and are never cited.

## Judgement calls (documented so they can be challenged)

* **Backups / data flows with an unstated block status.** `evidence_32` shows `backup_9287` in a
  recovery console with no restore block, but it never prints a restore permission. The
  extraction records `restore_allowed: null` (stated facts only). Policy then treats a retained
  backup or flow as a recreation path **until evidence shows it blocked / disabled**. That
  follows rule 14 ("restore access can be blocked") and the definition of COMPLETE ("no ...
  restore path can recreate data").
* **Catalog link vs. screenshot content (case_63).** Catalog row `activity_4008` links
  `marketing_001` to kwame-mensah@proton.me / user_09, but the screenshot `evidence_60` shows a
  different person (Soo-jin Park, sj.park@naver.com, not in `user_identities.csv`). All 11
  other catalog links agree with their artifacts. The marketing screen is the only static
  asset without a date in its filename and uses the hand-made `_001` numbering, so it reads
  as a template image. The link is kept, and every run prints a conflict warning (the only
  one on this dataset).

## Known limits of the public data

Some sample answers include resources that no participant-visible artifact ties to the subject
(e.g. `account_3136` for case_25 is only a bare 404 read-back and a `DELETE_RECORD` claim;
`audit_record_6645` for case_18 appears nowhere). We do not guess these. Narrow exception
(`code/accounts.py`): a primary account submitted by the deletion worker within 3 h before a
batch report is assigned when it is the only unlinked submission and only one request in that
batch lacks an account.
