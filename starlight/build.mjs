#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
process.chdir(__dirname);

process.env.ASTRO_TELEMETRY_DISABLED = '1';

const startTime = Date.now();
const keepalive = setInterval(() => {
  const elapsed = Math.round((Date.now() - startTime) / 1000);
  const mem = (process.memoryUsage().rss / 1024 / 1024).toFixed(0);
  process.stdout.write(`   [astro-build progress: ${elapsed}s | memory: ${mem}MB]\n`);
}, 5000);

try {
  const { cli } = await import('./node_modules/astro/dist/cli/index.js');
  await cli(['node', 'astro', 'build']);
  console.log('\n[+] Astro Starlight build finished successfully!');
} catch (err) {
  console.error('\n[-] Astro Starlight build error:', err);
  process.exit(1);
} finally {
  clearInterval(keepalive);
}
