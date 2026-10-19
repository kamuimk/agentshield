// Run after `cargo build --example dashboard_fixture` with Playwright available.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';

const engines = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const browserType = engines[process.env.AGENTSHIELD_BROWSER || 'chromium'];
assert.ok(browserType, 'supported browser engine required');
const adapter = await readFile(new URL('./dashboard-host.mjs', import.meta.url));
const host = createServer((request, response) => {
    response.setHeader('content-type', request.url === '/adapter.mjs' ? 'text/javascript' : 'text/html');
    response.end(request.url === '/adapter.mjs' ? adapter : '<!doctype html><title>AgentShield host fixture</title><div id="panel" style="height:900px"></div>');
});
host.listen(0, '127.0.0.1');
await once(host, 'listening');
const parent = `http://127.0.0.1:${host.address().port}`;
const fixture = spawn(process.env.AGENTSHIELD_DASHBOARD_FIXTURE || fileURLToPath(new URL('../target/debug/examples/dashboard_fixture', import.meta.url)), [parent, '10000'], { stdio: ['ignore', 'pipe', 'inherit'] });
let browser;
try {
    const url = await Promise.race([
        new Promise((resolve, reject) => {
            let output = '';
            fixture.stdout.on('data', (chunk) => { output += chunk; if (output.includes('\n')) resolve(output.split('\n')[0]); });
            fixture.once('error', reject);
            fixture.once('exit', () => reject(new Error('fixture exited before ready')));
        }),
        new Promise((_, reject) => { const timer = setTimeout(() => reject(new Error('fixture startup timeout')), 10000); timer.unref(); }),
    ]);
    browser = await browserType.launch({ headless: true });
    const page = await browser.newPage();
    const errors = [];
    const urls = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('request', (request) => urls.push(request.url()));
    await page.goto(parent);
    const mount = (token) => page.evaluate(async ({ url, token }) => {
        const { mountAgentShield } = await import('/adapter.mjs');
        window.shield = mountAgentShield({ container: document.getElementById('panel'), url, token, timeoutMs: 5000 });
        return window.shield.ready;
    }, { url, token });
    const reader = 'reader-token-000000000000000000000';
    const control = 'control-token-00000000000000000000';
    const manifest = await mount(reader);
    assert.deepEqual(manifest.capabilities, ['observe']);
    assert.equal(manifest.protection.system_egress_enforced, false);
    let frame = page.frames().find((frame) => frame.url() === `${url}/embed`);
    // A quiet stream must become connected before the first audit event.
    await frame.waitForFunction(() => document.getElementById('connectionStatus').textContent === 'Connected', null, { timeout: 4000 });
    assert.equal(await frame.evaluate(() => document.getElementById('logTableBody').textContent.includes('stream.example.test')), false, 'connection must precede the first audit event');
    await frame.waitForFunction(() => document.getElementById('logTableBody').textContent.includes('stream.example.test'));
    assert.equal(await frame.locator('#policySaveButton').isVisible(), false);
    assert.equal(await frame.locator('#policyEditor').evaluate((element) => element.readOnly), true);
    assert.equal(await frame.locator('#askSection').isVisible(), false);
    const status = await frame.evaluate(async () => (await apiFetch('/api/policy', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: '{"default":"allow","rules":[]}' })).status);
    assert.equal(status, 403);
    const logs = await frame.evaluate(async () => (await apiFetch('/api/logs')).json());
    assert.equal(logs[0].request_body, undefined);
    assert.equal(await frame.locator('img').count(), 0);
    assert.equal(await frame.evaluate(() => Boolean(window.injected)), false);
    assert.equal(await frame.evaluate(() => sessionStorage.getItem('agentshield_token')), null);
    assert.equal(await frame.evaluate(() => localStorage.getItem('agentshield_theme')), null);
    await page.evaluate(() => window.shield.setTheme('light'));
    await frame.waitForFunction(() => document.documentElement.dataset.theme === 'light');
    // A forged message from the host window is not an iframe-origin message.
    await page.evaluate(() => window.postMessage({ protocol: 'agentshield.dashboard.v1', type: 'error' }, location.origin));
    assert.equal(await page.locator('iframe').count(), 1);
    await page.evaluate(() => window.shield.dispose());
    assert.equal(await page.locator('iframe').count(), 0);
    // A transport that never supplies response headers must not leave the UI waiting forever.
    await page.route('**/api/logs/stream', () => {});
    await mount(reader);
    frame = page.frames().find((frame) => frame.url() === `${url}/embed`);
    await frame.waitForFunction(() => document.getElementById('connectionStatus').textContent === 'Disconnected', null, { timeout: 12000 });
    await page.unroute('**/api/logs/stream');
    await frame.waitForFunction(() => document.getElementById('connectionStatus').textContent === 'Connected', null, { timeout: 7000 });
    await frame.waitForFunction(() => document.getElementById('logTableBody').textContent.includes('stream.example.test'));
    await page.evaluate(() => window.shield.dispose());
    const controlManifest = await mount(control);
    assert.deepEqual(controlManifest.capabilities, ['observe', 'policy:write', 'ask:resolve']);
    frame = page.frames().find((frame) => frame.url() === `${url}/embed`);
    await frame.waitForSelector('#ask-fixture-ask');
    assert.equal(await frame.locator('img').count(), 0);
    await frame.getByRole('button', { name: 'Allow', exact: true }).click();
    await frame.waitForFunction(() => !document.getElementById('ask-fixture-ask'));
    assert.deepEqual(await frame.evaluate(async () => (await apiFetch('/api/ask/pending')).json()), []);
    await frame.getByRole('button', { name: 'Policy', exact: true }).click();
    await frame.locator('#policyEditor').fill('{"default":"allow","rules":[]}');
    await frame.getByRole('button', { name: 'Save Policy', exact: true }).click();
    await frame.waitForFunction(() => document.getElementById('policySaveStatus').textContent.startsWith('Saved'));
    assert.equal((await frame.evaluate(async () => (await apiFetch('/api/policy')).json())).default, 'allow');
    await page.evaluate(() => window.shield.dispose());
    await assert.rejects(mount('invalid-token-00000000000000000000'));
    assert.equal(await page.locator('iframe').count(), 0);
    assert.equal(urls.some((url) => url.includes(reader) || url.includes(control) || url.includes('?token=')), false);
    assert.deepEqual(errors, []);
    console.log('PASS: embedded reader/control permissions, policy/ASK effects, SSE, XSS, themes, token handling and cleanup');
} finally {
    await browser?.close();
    fixture.kill('SIGTERM');
    host.closeAllConnections();
    await new Promise((resolve) => host.close(resolve));
}
