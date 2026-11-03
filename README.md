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

## Safety

No exploit development happens in this repo. It only inspects versions, process
flags, and network telemetry on ephemeral GitHub-hosted runners.
