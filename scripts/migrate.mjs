import { readFile } from 'node:fs/promises';
import { database, closeDatabase } from '../server/db.mjs';
try { await database({ migration:true }).query(await readFile(new URL('../db/001-initial.sql',import.meta.url),'utf8')); console.log('Database schema ready.'); }
finally { await closeDatabase(); }
