// Local stand-in for attacker infrastructure. Serves the fingerprinting page
// and records when it flags the browser as a vulnerable target.
// No exploit code exists on this server — it only observes targeting.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const PORT = 8931;
const PAGE = path.join(__dirname, 'attacker-page.html');
const MARKER_DIR = path.join(__dirname, '..', '.demo-state');

const server = http.createServer((req, res) => {
  const url = req.url ?? '/';
  if (url.startsWith('/stage-2')) {
    fs.mkdirSync(MARKER_DIR, { recursive: true });
    fs.writeFileSync(path.join(MARKER_DIR, 'target-confirmed'), url);
    console.log('[attacker-site] target confirmed vulnerable; stage-2 requested:', url);
    res.writeHead(204);
    res.end();
    return;
  }
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end(fs.readFileSync(PAGE, 'utf8'));
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('[attacker-site] serving fingerprinting page on 127.0.0.1:' + PORT);
});
