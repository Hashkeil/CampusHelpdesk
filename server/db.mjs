import pg from 'pg';
let pool;
// Neon's pooled endpoint (PgBouncer, host contains "-pooler") silently ignores the statement_timeout startup
// parameter, so pooled connections rely on the client-side query_timeout instead.
function poolOptions(connectionString) {
  const pooled = new URL(connectionString).hostname.includes('-pooler');
  return { connectionString, max: 3, connectionTimeoutMillis: 5000, idleTimeoutMillis: 10000, query_timeout: 5000, ...(pooled ? {} : { statement_timeout: 5000 }) };
}
export function database({ migration = false } = {}) {
  const connectionString = (migration && process.env.MIGRATION_DATABASE_URL) || process.env.DATABASE_URL;
  if (!connectionString) throw new Error('DATABASE_URL is required');
  pool ??= new pg.Pool(poolOptions(connectionString));
  return pool;
}
export async function closeDatabase() { if (pool) { await pool.end(); pool = undefined; } }
