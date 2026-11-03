// Reports the browser build pinned by the installed playwright-core, before any
// browser is downloaded. The `revision` field is the Chromium build id that
// `npx playwright install chromium` resolves and fetches.
const fs = require('node:fs');
const path = require('node:path');

const corePkg = path.join('node_modules', 'playwright-core', 'package.json');
const registryPath = path.join('node_modules', 'playwright-core', 'browsers.json');

for (const f of [corePkg, registryPath]) {
  if (!fs.existsSync(f)) {
    console.error(`missing ${f} — run \`npm install\` first`);
    process.exit(1);
  }
}

const { version } = JSON.parse(fs.readFileSync(corePkg, 'utf8'));
const registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));

console.log(`playwright-core version: ${version}`);
console.log(`browser cache directory: ${path.join(process.env.HOME ?? '~', '.cache', 'ms-playwright')}`);
console.log('\npinned chromium entries in browsers.json:');
const chromiumEntries = registry.browsers.filter((b) => b.name.includes('chromium'));
console.log(JSON.stringify(chromiumEntries, null, 2));
