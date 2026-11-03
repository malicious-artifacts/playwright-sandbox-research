// IMPACT-CHAIN DEMO ORCHESTRATOR — research artifact.
//
// Chain demonstrated:
//   [REAL]      victim browser launched with Playwright DEFAULTS (sandbox off)
//   [REAL]      browser visits the "attacker site" (simulated malicious web content)
//   [REAL]      attacker page fingerprints the build and confirms vulnerability
//   [SIMULATED] the CVE-2026-118306 memory-corruption trigger itself — NOT reproduced.
//               After the targeting confirmation we proceed AS IF it succeeded.
//   [REAL]      payload runs with the same kernel privileges exploited native code
//               would have inside an unsandboxed renderer: decoy credential
//               access + C2 beacon
//
// Everything except the trigger is real behavior; the missing link is assessed
// via authoritative records (NVD "execute arbitrary code outside the sandbox",
// CISA KEV for older pinned builds). See README for the full argument.
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

const MARKER = path.join(__dirname, '..', '.demo-state', 'target-confirmed');

// Starting the simulated attacker site in-process (it listens on 127.0.0.1:8931)
require('./server.js');

function seccompSnapshot() {
  // Compact renderer-sandbox check (same method as scripts/02-sandbox-audit.js)
  if (!fs.existsSync('/proc')) {
    console.log('[privileges] /proc unavailable on this platform — skipping (Linux CI reports it)');
    return [];
  }
  const procs = [];
  for (const pid of fs.readdirSync('/proc')) {
    if (!/^\d+$/.test(pid)) continue;
    let cmdline;
    try {
      cmdline = fs.readFileSync(path.join('/proc', pid, 'cmdline'), 'utf8');
    } catch {
      continue;
    }
    if (!cmdline.includes('ms-playwright')) continue;
    const typeMatch = cmdline.match(/--type=(\S+)/);
    const procType = typeMatch ? typeMatch[1] : 'browser (main)';
    if (procType !== 'renderer') continue;
    let mode = 'n/a';
    try {
      const statusText = fs.readFileSync(path.join('/proc', pid, 'status'), 'utf8');
      const seccompMatch = statusText.match(/^Seccomp:\s*(\d+)$/m);
      mode = seccompMatch ? seccompMatch[1] : 'n/a';
    } catch {}
    procs.push({ pid: Number(pid), seccomp: mode });
  }
  return procs;
}

function waitForMarker(ms) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (fs.existsSync(MARKER)) return true;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200);
  }
  return fs.existsSync(MARKER);
}

(async () => {
  console.log('=== [1] simulated attacker site is up (see [attacker-site] log above) ===');

  console.log('\n=== [2] launching victim browser with Playwright DEFAULTS ===');
  const browser = await chromium.launch();
  const page = await browser.newPage();

  console.log('\n=== [3] victim browses to attacker-controlled content ===');
  await page.goto('http://127.0.0.1:8931/');
  const pageStatus = await page.evaluate(() => document.body.innerText);
  console.log('[victim page says]', pageStatus.replace(/\n/g, ' | '));

  console.log('\n=== [4] waiting for attacker-side targeting confirmation ===');
  const confirmed = waitForMarker(10000);
  if (!confirmed) {
    console.log('attacker site never confirmed targeting — demo cannot proceed');
    await browser.close();
    process.exit(1);
  }

  console.log(`
*****************************************************************
*  SIMULATION STEP — the memory-corruption trigger (CVE-2026-118306)
*  is NOT reproduced here. Proceeding AS IF the renderer exploit
*  succeeded, to demonstrate everything that happens afterwards.
*****************************************************************`);

  for (const r of seccompSnapshot()) {
    console.log(`[privileges] renderer pid ${r.pid} Seccomp=${r.seccomp}` +
      (r.seccomp === '0' ? '  <= NO SANDBOX: native code here = user-level host access' : ''));
  }

  console.log('\n=== [5] post-exploitation payload (in-process: same user, no seccomp) ===');
  await require('./payload.js');

  console.log('\n=== demo complete — check harden-runner insights for the egress trail ===');
  await browser.close();
  process.exit(0);
})();
