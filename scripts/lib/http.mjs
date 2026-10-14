import { setTimeout as delay } from 'node:timers/promises';

export function retryAfterMs(value, now = Date.now()) {
  if (!value) return 0;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1000;
  const date = Date.parse(value);
  return Number.isFinite(date) ? Math.max(0, date - now) : 0;
}

// One client serializes requests to a rate-limited service. A long Retry-After
// defers the remaining queries instead of ignoring the server's cooldown.
export function createJsonClient({ fetchImpl = globalThis.fetch, sleep = delay,
  clock = Date.now, minIntervalMs = 6000, maxAttempts = 3,
  maxWaitMs = 30000, timeoutMs = 30000 } = {}) {
  let nextRequestAt = 0;
  let queue = Promise.resolve();
  async function request(url, label) {
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const wait = Math.max(0, nextRequestAt - clock());
      if (wait > maxWaitMs) {
        const error = new Error(`${label}: deferred during service cooldown`);
        error.retry_after_ms = wait;
        throw error;
      }
      if (wait) await sleep(wait);
      nextRequestAt = clock() + minIntervalMs;
      let response;
      try {
        response = await fetchImpl(url, {
          headers: { 'user-agent': 'mard-hybrid-telemetry/0.2.0 (+public contextual telemetry)' },
          signal: AbortSignal.timeout(timeoutMs)
        });
      } catch (error) {
        if (attempt === maxAttempts) throw new Error(`${label}: request failed (${error.name || 'network error'})`);
        nextRequestAt = Math.max(nextRequestAt, clock() + 2000 * 2 ** (attempt - 1));
        continue;
      }
      if (!response.ok) {
        const retryable = response.status === 429 || response.status >= 500;
        const cooldown = Math.max(retryAfterMs(response.headers.get('retry-after'), clock()), 2000 * 2 ** (attempt - 1));
        if (retryable) nextRequestAt = Math.max(nextRequestAt, clock() + cooldown);
        const error = new Error(`${label}: HTTP ${response.status}`);
        error.http_status = response.status;
        error.retry_after_ms = retryable ? cooldown : null;
        if (!retryable || attempt === maxAttempts || cooldown > maxWaitMs) throw error;
        continue;
      }
      const raw = await response.text();
      let json;
      try { json = JSON.parse(raw); }
      catch { throw new Error(`${label}: invalid JSON response`); }
      // ArticleList can legitimately return an empty list. A JSON error object
      // or an unexpected schema must never become a successful zero result.
      if (!json || !Array.isArray(json.articles)) throw new Error(`${label}: missing ArticleList articles array`);
      return { json, raw, attempts: attempt };
    }
  }
  return (url, label) => {
    const task = queue.then(() => request(url, label));
    queue = task.catch(() => {});
    return task;
  };
}
