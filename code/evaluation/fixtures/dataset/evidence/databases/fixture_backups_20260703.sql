-- Fixture backup inventory (synthetic). Captured at: 2026-07-03T08:00:00Z
CREATE TABLE backup_restore_entries (resource_id TEXT, owner_email TEXT, archive_key TEXT, restore_allowed INTEGER, updated_at TEXT);
INSERT INTO backup_restore_entries VALUES ('backup_9111', 'b.subject@example.test', 'archive/customer-data/backup_9111.tar.zst', 0, '2026-07-03T08:00:00Z');
