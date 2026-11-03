# Playwright sandbox research

Verification repo for the Nov 2026 [@nisten](https://x.com/nisten/status/2117389727016108541)
claim that Playwright 1.64.1 ships a Chromium build with a sandbox-escape bug
(CVE-2026-118306 / -118331 / -118348 / -118344), and that Playwright disables the
Chromium sandbox by default.

## Questions under investigation

1. Does the `playwright` npm package expose users to this? (i.e. does the browser
   build that `npx playwright install` downloads contain the vulnerable code?)
2. Does it achieve RCE in practice?

## Phase 1 — establish facts (current)

- **Fingerprint**: read the browser registry pinned inside `playwright-core@1.64.1`
  (`browsers.json`) and record the exact Chromium build revision, then report the
  installed binary's version. Answers "which Chromium are users actually running".
- **Sandbox audit**: launch via `chromium.launch()` with **default options only**,
  enumerate the browser process tree, and report (a) whether `--no-sandbox` was
  passed and (b) each process's seccomp mode from `/proc/<pid>/status`
  (`0` = sandbox disabled, `2` = seccomp filter active). Runs for both the default
  headless-shell and the full Chromium build (`channel: "chromium"`).
- **Egress telemetry**: `step-security/harden-runner` in audit mode wraps the whole
  job, so the `npx playwright install` step shows exactly which domains the
  browser download touches.

## Phase 2 — planned

- Map the fingerprinted Chromium version against the fix versions for the four
  CVEs (Chrome release notes) to confirm or deny exposure per CVE.
- Impact analysis for the RCE question: with the Chromium sandbox off, any
  renderer memory-safety bug is host code execution by definition; the "escapes
  even an enabled sandbox" part of the claim stays **unverified** until a PoC
  exists.
- Check older Playwright pins too — per nisten's thread, older releases bundle
  older Chromium and may miss more fixes.

## Phase 1 results (run 41616754224, 2026-11-03)

| Claim | Verdict | Evidence |
|---|---|---|
| playwright@1.64.1 bundles a vulnerable Chromium | **CONFIRMED** | `browsers.json` pins chromium + chromium-headless-shell rev 1248 = **156.0.8078.4** (UA-verified); the four CVEs are fixed only in **156.0.8078.73** ([Chrome Stable 2026-10-27](https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_0562499947.html)) |
| Playwright disables the Chromium sandbox by default | **CONFIRMED** | default `chromium.launch()`: every process incl. renderers runs `--no-sandbox` with `Seccomp: 0`; network utility runs `--service-sandbox-type=none`. Same for headless-shell and full Chromium builds |
| "The bug escapes the sandbox" / achieves RCE | **CREDIBLE — NOT REPRODUCED** | CVE-2026-118306 (Critical, FileSystem memory corruption) and CVE-2026-118331 (Critical, FileAPI input validation) are described as allowing code execution *outside* the sandbox. Under Playwright defaults there is no sandbox to escape, so any working renderer exploit = host RCE. No public PoC exists; we did not attempt weaponization |

**Answers to the review questions:**
1. *Does this happen with the playwright npm package?* **Yes** — the package itself is clean, but it pins the browser build, and `npx playwright install` fetches vulnerable 156.0.8078.4.
2. *Does this achieve RCE?* **Structurally yes under default config** (sandbox off + critical CVEs in pinned build); not demonstrated with a working exploit here.

Harden-runner egress insights for this run:
https://app.stepsecurity.io/github/malicious-artifacts/playwright-sandbox-research/actions/runs/41616754224

## Phase 2 — impact-chain PoC (`poc/`, workflow `poc-impact.yml`)

An end-to-end demonstration of the attack chain with **one explicitly simulated
step**. What is real vs simulated:

| Stage | Status |
|---|---|
| Delivery: victim browser (Playwright defaults) visits attacker-controlled page | **REAL** (localhost stand-in site) |
| Targeting: page fingerprints the build, confirms 156.0.8078.4 is vulnerable | **REAL** (`poc/attacker-page.html`) |
| Renderer memory-corruption trigger (CVE-2026-118306 etc.) | **SIMULATED — deliberately not reproduced** |
| Post-exploitation: credential access (`~/.ssh`, `~/.aws`, `.env`) | **REAL, decoy values only** (`poc/payload.js`) |
| C2 egress beacon | **REAL, dummy data to a public echo endpoint** |

**Why the trigger is not reproduced:** the pinned builds are unpatched in the
wild, three of the older-pin CVEs are CISA KEV (exploitation already confirmed
by CISA — exploitability is not in question for those), and no public PoC
exists. Publishing a weaponized exploit would arm attackers against every user
still on unpatched pinned builds. The trigger's feasibility is assessed from
authoritative records instead: NVD describes CVE-2026-118306 as allowing
"arbitrary code execution **outside** the sandbox".

**Control job** (`impact-demo-blocked`): the same chain under harden-runner
block mode with a minimal allowlist — the C2 beacon must fail — plus a
sandbox-ENABLED launch audit (`Seccomp: 2` on renderers) showing the
configuration-level fix.

## Safety

No exploit development happens in this repo. It only inspects versions, process
flags, and network telemetry on ephemeral GitHub-hosted runners.
