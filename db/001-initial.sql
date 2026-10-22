BEGIN;
CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY,
  email text UNIQUE NOT NULL,
  name text NOT NULL CHECK (length(name) BETWEEN 2 AND 80),
  password_hash text NOT NULL,
  role text NOT NULL DEFAULT 'student' CHECK (role IN ('student','staff','admin')),
  blocked boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash text PRIMARY KEY,
  csrf_token text NOT NULL,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS tickets (
  id uuid PRIMARY KEY,
  owner_id uuid NOT NULL REFERENCES users(id),
  assigned_to uuid REFERENCES users(id),
  title text NOT NULL CHECK (length(title) BETWEEN 3 AND 120),
  body text NOT NULL CHECK (length(body) BETWEEN 10 AND 4000),
  category text NOT NULL CHECK (category IN ('IT support','Facilities','Academic','Other')),
  priority text NOT NULL CHECK (priority IN ('low','normal','high')),
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','resolved')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tickets_owner ON tickets(owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS tickets_assignee ON tickets(assigned_to, created_at DESC);
CREATE TABLE IF NOT EXISTS replies (
  id uuid PRIMARY KEY,
  ticket_id uuid NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
  author_id uuid NOT NULL REFERENCES users(id),
  body text NOT NULL CHECK (length(body) BETWEEN 1 AND 2000),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS replies_ticket ON replies(ticket_id, created_at);
CREATE TABLE IF NOT EXISTS rate_limits (
  key text PRIMARY KEY,
  hits integer NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event text NOT NULL,
  actor_id uuid,
  target_id uuid,
  request_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS security_alerts (
  id uuid PRIMARY KEY,
  event text NOT NULL,
  status text NOT NULL CHECK (status IN ('pending','delivered','failed','not_configured')),
  created_at timestamptz NOT NULL DEFAULT now()
);
COMMIT;
