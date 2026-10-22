import pg from 'pg';
let pool;
export function database() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
  pool ??= new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 3, connectionTimeoutMillis: 5000, idleTimeoutMillis: 10000, statement_timeout: 5000 });
  return pool;
}
export async function closeDatabase() { if (pool) { await pool.end(); pool = undefined; } }
