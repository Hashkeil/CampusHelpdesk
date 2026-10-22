BEGIN;
CREATE TABLE IF NOT EXISTS attachments (
  id uuid PRIMARY KEY,
  ticket_id uuid NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
  uploader_id uuid NOT NULL REFERENCES users(id),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  content_type text NOT NULL CHECK (content_type IN ('image/png','image/jpeg','application/pdf','text/plain; charset=utf-8','text/csv; charset=utf-8')),
  content bytea NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 3145728),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS attachments_ticket ON attachments(ticket_id, created_at);
COMMIT;
