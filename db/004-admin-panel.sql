BEGIN;
CREATE INDEX IF NOT EXISTS audit_events_actor ON audit_events(actor_id, event, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_event ON audit_events(event, id DESC);
CREATE INDEX IF NOT EXISTS audit_events_created ON audit_events(created_at);
COMMIT;
