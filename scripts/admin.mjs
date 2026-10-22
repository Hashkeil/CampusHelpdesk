import { database, closeDatabase } from '../server/db.mjs';
const address = process.argv[2]?.trim().toLowerCase();
if (!address) throw new Error('Usage: npm run admin -- your-email@example.com');
try {
  const result = await database().query("UPDATE users SET role='admin' WHERE email=$1 RETURNING id",[address]);
  if (!result.rowCount) throw new Error('Register this account first.');
  console.log('Administrator role assigned. Sign in again.');
} finally { await closeDatabase(); }
