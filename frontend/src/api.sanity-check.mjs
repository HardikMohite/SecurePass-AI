/**
 * api.sanity-check.mjs — standalone sanity check for src/api.js
 *
 * Not part of the app bundle and not a real test suite (the project has
 * no test runner configured yet — package.json only has vite). This is
 * a quick, dependency-free script that mocks `fetch` and runs it under
 * plain Node to sanity-check the request/refresh/redirect logic in
 * isolation, per the ticket ("build and unit-sanity-check the API
 * client in isolation").
 *
 * Run with:  node src/api.sanity-check.mjs
 */

import assert from 'node:assert/strict';

// Mock `window` so redirectToLogin()'s browser branch is exercised and
// observable instead of silently no-op-ing under Node.
global.window = { location: {} };

const { apiFetch, apiJson, login, logout, getAccessToken, clearTokens } = await import('./api.js');

let calls = [];
let scriptedResponses = [];

function mockFetch(url, options = {}) {
  calls.push({ url, options });
  const next = scriptedResponses.shift();
  if (!next) throw new Error(`mockFetch called with no scripted response left: ${url}`);
  return Promise.resolve({
    ok: next.status >= 200 && next.status < 300,
    status: next.status,
    json: async () => next.body,
  });
}

function reset() {
  calls = [];
  scriptedResponses = [];
  clearTokens();
  global.fetch = mockFetch;
}

async function test(name, fn) {
  reset();
  try {
    await fn();
    console.log(`ok   - ${name}`);
  } catch (err) {
    console.error(`FAIL - ${name}`);
    console.error(err);
    process.exitCode = 1;
  }
}

await test('login stores access + refresh tokens and does not send Authorization', async () => {
  scriptedResponses.push({
    status: 200,
    body: { user: { id: 1 }, access_token: 'access-1', refresh_token: 'refresh-1' },
  });

  await login('user@example.com', 'hunter2', false);

  assert.equal(getAccessToken(), 'access-1');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, '/api/auth/login');
  assert.equal(calls[0].options.headers.has('Authorization'), false);
});

await test('apiFetch attaches Authorization: Bearer <token> when authenticated', async () => {
  scriptedResponses.push({ status: 200, body: { access_token: 'a', refresh_token: 'r' } });
  await login('user@example.com', 'hunter2');

  scriptedResponses.push({ status: 200, body: { ok: true } });
  await apiFetch('/api/auth/profile');

  const profileCall = calls[calls.length - 1];
  assert.equal(profileCall.options.headers.get('Authorization'), 'Bearer a');
});

await test('a 401 triggers exactly one refresh call and retries the original request', async () => {
  scriptedResponses.push({ status: 200, body: { access_token: 'stale', refresh_token: 'refresh-1' } });
  await login('user@example.com', 'hunter2');

  // 1) original request 401s, 2) refresh succeeds, 3) retried request succeeds
  scriptedResponses.push({ status: 401, body: { error: 'Token expired' } });
  scriptedResponses.push({ status: 200, body: { access_token: 'fresh' } });
  scriptedResponses.push({ status: 200, body: { history: [] } });

  const res = await apiFetch('/api/auth/history');
  const data = await res.json();

  assert.deepEqual(data, { history: [] });
  assert.equal(getAccessToken(), 'fresh');
  assert.equal(calls.length, 4); // login + 401 + refresh + retry
  assert.equal(calls[2].url, '/api/auth/refresh');
  assert.equal(calls[2].options.headers.Authorization, 'Bearer refresh-1');
  assert.equal(calls[3].options.headers.get('Authorization'), 'Bearer fresh');
});

await test('refresh failure clears tokens and redirects to /login.html', async () => {
  scriptedResponses.push({ status: 200, body: { access_token: 'stale', refresh_token: 'dead-refresh' } });
  await login('user@example.com', 'hunter2');

  scriptedResponses.push({ status: 401, body: { error: 'Token expired' } });
  scriptedResponses.push({ status: 401, body: { error: 'Refresh token expired' } });

  global.window.location.href = ''; // reset before assertion
  await assert.rejects(() => apiFetch('/api/auth/history'));

  assert.equal(getAccessToken(), null);
  assert.equal(global.window.location.href, '/login.html');
});

await test('apiJson throws with .status and .data on a non-2xx response', async () => {
  scriptedResponses.push({ status: 400, body: { error: 'Email and password are required.' } });
  await assert.rejects(
    () => apiJson('/api/auth/login', { method: 'POST', auth: false, body: '{}' }),
    (err) => {
      assert.equal(err.status, 400);
      assert.equal(err.data.error, 'Email and password are required.');
      return true;
    }
  );
});

await test('logout sends the refresh token and clears local state either way', async () => {
  scriptedResponses.push({ status: 200, body: { access_token: 'a', refresh_token: 'r' } });
  await login('user@example.com', 'hunter2');

  scriptedResponses.push({ status: 200, body: { message: 'Logged out successfully.' } });
  await logout();

  assert.equal(getAccessToken(), null);
  const logoutCall = calls[calls.length - 1];
  assert.equal(logoutCall.url, '/api/auth/logout');
  assert.equal(JSON.parse(logoutCall.options.body).refresh_token, 'r');
});

if (process.exitCode) {
  console.error('\nSanity check FAILED');
  process.exit(1);
} else {
  console.log('\nAll sanity checks passed.');
}
