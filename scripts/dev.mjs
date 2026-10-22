import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { handler } from '../server/api.mjs';
const assets = new Map([['/',['index.html','text/html']],['/app.js',['app.js','text/javascript']],['/styles.css',['styles.css','text/css']]]);
http.createServer(async (req,res) => {
  try {
    const path = new URL(req.url,'http://localhost:8888').pathname;
    if (path.startsWith('/api/')) {
      const chunks = []; let size = 0;
      for await (const chunk of req) { size += chunk.length; if (size > 16384) { res.writeHead(413); res.end('Request too large'); return; } chunks.push(chunk); }
      const result = await handler({ httpMethod:req.method, headers:req.headers, rawUrl:`http://localhost:8888${req.url}`, body:Buffer.concat(chunks).toString() });
      res.writeHead(result.statusCode,result.headers); res.end(result.body); return;
    }
    const asset = assets.get(path);
    if (!asset || req.method !== 'GET') { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200,{ 'Content-Type':`${asset[1]}; charset=utf-8`, 'X-Content-Type-Options':'nosniff', 'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'" });
    res.end(await readFile(new URL(`../public/${asset[0]}`,import.meta.url)));
  } catch { res.writeHead(500); res.end('Service unavailable'); }
}).listen(8888,'127.0.0.1',() => console.log('Campus Helpdesk: http://localhost:8888'));
