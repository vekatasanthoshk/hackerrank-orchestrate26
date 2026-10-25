-- Fixture customer-profile snapshot (synthetic). Captured at: 2026-05-10T10:00:00Z
CREATE TABLE customer_profiles_primary (resource_id TEXT, email TEXT, phone TEXT, full_name TEXT, updated_at TEXT);
CREATE TABLE customer_profiles_reporting_replica (resource_id TEXT, email TEXT, phone TEXT, full_name TEXT, updated_at TEXT);
INSERT INTO customer_profiles_primary VALUES ('account_9020', 'a.subject.jr@example.test', '+1 555 010 0902', 'Ada Example Jr', '2026-05-10T10:00:00Z');
INSERT INTO customer_profiles_reporting_replica VALUES ('account_9001', 'old.a@example.test', NULL, 'Ada Example', '2026-05-10T10:00:00Z');
INSERT INTO customer_profiles_reporting_replica VALUES ('account_9020', 'a.subject.jr@example.test', '+1 555 010 0902', 'Ada Example Jr', '2026-05-10T10:00:00Z');
