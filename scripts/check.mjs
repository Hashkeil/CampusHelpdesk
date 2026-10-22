import { readdir } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
async function walk(path) {
  for (const entry of await readdir(path,{ withFileTypes:true })) {
    const file = `${path}/${entry.name}`;
    if (entry.isDirectory()) await walk(file);
    else if (/\.(mjs|js)$/.test(file)) {
      const result = spawnSync(process.execPath,['--check',file],{ stdio:'inherit' });
      if (result.status) process.exit(result.status);
    }
  }
}
for (const path of ['server','scripts','public','netlify','tests']) await walk(path);
console.log('JavaScript syntax checks passed.');
