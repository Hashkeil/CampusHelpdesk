import { readdir, readFile } from 'node:fs/promises';
import { database, closeDatabase } from '../server/db.mjs';
const directory = new URL('../db/',import.meta.url);
try {
  // Every migration is idempotent, so all files are applied in name order on each run.
  for (const file of (await readdir(directory)).filter(name => name.endsWith('.sql')).sort()) await database({ migration:true }).query(await readFile(new URL(file,directory),'utf8'));
  console.log('Database schema ready.');
}
finally { await closeDatabase(); }
