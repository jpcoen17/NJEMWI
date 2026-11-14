// Smoke test signed preflight untuk agent2 (ESM)
import crypto from 'crypto';
import fs from 'fs';
import https from 'https';

const env = fs.readFileSync('/home/agentuser/agent-jembot2/.env', 'utf8');
const SECRET = env.match(/AGENT_GAMES_HMAC_SECRET=(\S+)/)[1];
const URL2 = process.env.URL2 || 'https://partnerships-senators-differ-nicole.trycloudflare.com/agent';

const body = JSON.stringify({ type: 'agent-games.preflight' });
const sig = crypto.createHmac('sha256', SECRET).update(body).digest('hex');
const u = new URL(URL2);
const req = https.request({ hostname: u.hostname, path: u.pathname, method: 'POST',
  headers: { 'Content-Type': 'application/json', 'x-agent-games-signature': sig } }, res => {
  let d = ''; res.on('data', c => d += c); res.on('end', () => console.log('preflight:', res.statusCode, d));
});
req.on('error', e => console.log('ERR', e.message));
req.write(body); req.end();
