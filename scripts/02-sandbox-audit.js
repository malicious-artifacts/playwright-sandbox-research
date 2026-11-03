// Launches the bundled browser through Playwright's public API using DEFAULT
// options only, then inspects the resulting process tree on Linux:
//   - whether --no-sandbox was passed (chromiumSandbox defaults to false)
//   - each process's seccomp mode from /proc/<pid>/status (0 = off, 2 = filter)
// No commands are executed here; everything below is pure file reads. PIDs are
// validated numeric directory names from /proc before any path is built.
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

const PROC_DIR = '/proc';
// All Playwright-managed browser processes reference the ms-playwright cache
// path in their command line, whatever the binary is named.
const MANAGED_PROC = /ms-playwright/;
const PID_DIR = /^\d+$/;
const SECCOMP_MODE = /^Seccomp:\s*(\d+)$/m;
const PROC_TYPE = /--type=(\S+)/;

function readProcFile(pid, file) {
  // pid is guaranteed digits-only by the caller; join keeps the path normalized
  return fs.readFileSync(path.join(PROC_DIR, pid, file), 'utf8');
}

function snapshot() {
  const procs = [];
  for (const pid of fs.readdirSync(PROC_DIR)) {
    if (!PID_DIR.test(pid)) continue;
    let cmdline;
    try {
      cmdline = readProcFile(pid, 'cmdline');
    } catch {
      continue;
    }
    if (!MANAGED_PROC.test(cmdline)) continue;

    let seccomp = 'n/a';
    try {
      const statusText = readProcFile(pid, 'status');
      const match = statusText.match(SECCOMP_MODE);
      seccomp = match ? match[1] : 'n/a';
    } catch {}

    const typeMatch = cmdline.match(PROC_TYPE);
    procs.push({
      pid: Number(pid),
      type: typeMatch ? typeMatch[1] : 'browser (main)',
      seccompMode: seccomp,
      sandboxFlags: cmdline.split('\0').filter((a) => a.includes('sandbox')),
    });
  }
  return procs.sort((a, b) => a.pid - b.pid);
}

async function audit(label, opts = {}) {
  console.log(`\n=== launch: ${label} ===`);
  console.log('executablePath:', chromium.executablePath(opts));
  const browser = await chromium.launch(opts);
  const page = await browser.newPage();
  await page.goto('about:blank');
  await new Promise((r) => setTimeout(r, 1000)); // let child processes settle
  console.log('userAgent:', await page.evaluate(() => navigator.userAgent));
  const procs = snapshot();
  if (procs.length === 0) console.log('no browser processes found');
  for (const p of procs) {
    console.log(
      `pid ${p.pid}  type=${p.type}  Seccomp=${p.seccompMode}  sandboxFlags=${JSON.stringify(p.sandboxFlags)}`
    );
  }
  const renderers = procs.filter((p) => p.type === 'renderer');
  let verdict;
  if (renderers.length === 0) {
    verdict = 'NO RENDERER PROCESSES SEEN (probe needs adjustment)';
  } else if (renderers.every((p) => p.seccompMode === '0')) {
    verdict = 'CHROMIUM SANDBOX OFF for all renderers (seccomp mode 0) — renderer compromise == host code execution';
  } else if (renderers.some((p) => p.seccompMode === '2')) {
    verdict = 'seccomp filter active on >=1 renderer (sandbox on)';
  } else {
    verdict = 'mixed/unknown seccomp state';
  }
  console.log(`verdict: ${verdict}`);
  await browser.close();
}

(async () => {
  if (process.platform !== 'linux') {
    console.log(`/proc inspection is Linux-only; running on ${process.platform} — results will be partial`);
  }
  await audit('default options (headless)');
  await audit('full chromium build', { channel: 'chromium' });
})();
