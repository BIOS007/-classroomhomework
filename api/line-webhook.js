'use strict';
const { createHmac, timingSafeEqual } = require('node:crypto');

// Read the original byte stream, never JSON.stringify(req.body) for signature checking.
module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const send = (code, message) => { res.statusCode = code; res.end(message); };
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return send(405, 'POST required');
  }
  const secret = process.env.LINE_CHANNEL_SECRET;
  const relayKey = process.env.LINE_WEBHOOK_KEY;
  let target;
  try {
    target = new URL(process.env.APPS_SCRIPT_URL);
    if (target.origin !== 'https://script.google.com' ||
        !/^\/macros\/s\/[A-Za-z0-9_-]+\/exec$/.test(target.pathname) ||
        target.search || target.hash || target.username || target.password ||
        !secret || !relayKey || relayKey.length < 32) throw new Error();
  } catch {
    return send(503, 'Webhook configuration incomplete');
  }
  const signature = req.headers['x-line-signature'];
  if (typeof signature !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(signature)) {
    return send(401, 'Invalid signature');
  }
  try {
    const chunks = []; let length = 0;
    for await (const chunk of req) {
      const bytes = Buffer.from(chunk); length += bytes.length;
      if (length > 1024 * 1024) return send(413, 'Webhook too large');
      chunks.push(bytes);
    }
    const raw = Buffer.concat(chunks);
    const expected = createHmac('sha256', secret).update(raw).digest();
    const received = Buffer.from(signature, 'base64');
    if (received.length !== expected.length || !timingSafeEqual(received, expected)) {
      return send(401, 'Invalid signature');
    }
    let payload;
    try { payload = JSON.parse(raw.toString('utf8')); } catch { return send(400, 'Invalid JSON'); }
    if (!payload || !Array.isArray(payload.events) || payload.events.length > 100) {
      return send(400, 'Invalid events');
    }
    // LINE verification contains no events. No Apps Script cold start is needed.
    if (payload.events.length === 0) return send(200, 'OK');
    const upstream = await fetch(target, {
      method: 'POST', redirect: 'follow',
      headers: { 'Content-Type': 'application/json' },
      // Only verified LINE events are forwarded. No arbitrary upload action is accepted.
      body: JSON.stringify({ events: payload.events, destination: payload.destination, _relay_key: relayKey }),
      signal: AbortSignal.timeout(20000),
    });
    const result = await upstream.json();
    if (!upstream.ok || result?.success !== true || result?.status !== 'line_processed') {
      return send(502, 'Backend did not accept event');
    }
    return send(200, 'OK');
  } catch (error) {
    // Never log request bodies, room passcodes, URLs with credentials, or provider error text.
    return send(error?.name === 'TimeoutError' ? 504 : 502, 'Webhook delivery failed');
  }
};
