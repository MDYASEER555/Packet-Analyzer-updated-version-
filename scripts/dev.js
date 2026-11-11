import dotenv from 'dotenv';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
dotenv.config({ path: path.join(root, 'backend', '.env'), quiet: true });

const configuredHost = process.env.HOST || '127.0.0.1';
const host = ['0.0.0.0', '::', '::0'].includes(configuredHost) ? '127.0.0.1' : configuredHost;
const port = Number(process.env.PORT || 4000);
const healthUrl = `http://${host.includes(':') ? `[${host}]` : host}:${port}/api/health`;
const api = spawn(process.execPath, ['backend/server.js'], { cwd: root, stdio: 'inherit', windowsHide: true });
let web;
let stopping = false;

function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  if (web && web.exitCode === null) web.kill();
  if (api.exitCode === null) api.kill();
  process.exitCode = code;
}

process.on('SIGINT', () => stop(0));
process.on('SIGTERM', () => stop(0));

async function waitForApi() {
  const deadline = Date.now() + 120_000;
  while (!stopping && Date.now() < deadline) {
    if (api.exitCode !== null) throw new Error(`API exited with code ${api.exitCode}; Vite was not started.`);
    try {
      const response = await fetch(healthUrl, { signal: AbortSignal.timeout(1000) });
      if (response.ok) return;
    } catch { /* The API is still starting. */ }
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
  if (!stopping) throw new Error('API did not become ready within 120 seconds; Vite was not started.');
}

try {
  await waitForApi();
  if (!stopping) {
    console.log('API is ready; starting the web client.');
    web = spawn(process.execPath, [path.join(root, 'node_modules', 'vite', 'bin', 'vite.js'), 'frontend', '--config', 'frontend/vite.config.js', '--host', '127.0.0.1'], {
      cwd: root,
      stdio: 'inherit',
      windowsHide: true
    });
    web.on('error', (error) => {
      console.error(`Could not start the web client: ${error.message}`);
      stop(1);
    });
    web.on('exit', (code) => stop(code || 0));
  }
} catch (error) {
  if (!stopping) console.error(error.message);
  stop(1);
}

api.on('exit', (code) => {
  if (!stopping && web) stop(code || 0);
});
