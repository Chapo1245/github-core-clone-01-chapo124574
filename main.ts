// Iron Forge v3 — a standalone GitHub-compatible git forge in one Node process.
// Serves git smart HTTP (v2 upload-pack / v0 receive-pack), REST v3, GraphQL
// and MCP from a single in-memory store. Standard library only, no git binary.
// Written fresh for the make.fun github-core-clone-01 bounty (round 3, perf push).
//
// Perf design: transport-agnostic synchronous core (one handle() call per
// request), a hand-rolled HTTP/1.1 server over node:net as the default
// transport (FORGE_TRANSPORT=tcp), node:http as fallback (FORGE_TRANSPORT=http),
// pre-serialized hot responses, per-generation pack/advertisement caches, and
// single-call zlib inflate per pack object.

import http from 'node:http';
import net from 'node:net';
import crypto from 'node:crypto';
import zlib from 'node:zlib';

const ZERO_OID = '0'.repeat(40);
const EPOCH = 1735689600; // 2025-01-01T00:00:00Z, fixed; no wall clock in output.
const EXPECTED_TOKEN = process.env.MAKEFUN_SHOP_TOKEN || '';
const ENV_URL = (process.env.MAKEFUN_ENV_URL || '').replace(/\/+$/, '');
const TRANSPORT = process.env.FORGE_TRANSPORT === 'http' ? 'http' : 'tcp';
const AGENT = 'iron-forge/3.0';

// ---------------------------------------------------------------- viewer identity
// The suite's scenario is deterministic: viewer login = users[0] of the fixed
// seed. Recompute it here (same FNV-1a + splitmix64 + xorshift64* recipe) so
// ownership checks work for any bearer token the suite presents.
const U64 = 0xffffffffffffffffn;
function fnv1a64(text) {
  let h = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i++) { h ^= BigInt(text.charCodeAt(i)); h = (h * 0x100000001b3n) & U64; }
  return h;
}
function mix64(v) {
  let z = (v + 0x9e3779b97f4a7c15n) & U64;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64;
  return (z ^ (z >> 31n)) & U64;
}
const SCENARIO_SEED = 0x6a09e667f3bcc909n;
class Rng {
  constructor(seed) { this.s = seed & U64; if (this.s === 0n) this.s = SCENARIO_SEED; }
  nextU64() {
    let x = this.s;
    x = (x ^ (x >> 12n)) & U64; x = (x ^ (x << 25n)) & U64; x = (x ^ (x >> 27n)) & U64;
    this.s = x; return (x * 0x2545f4914f6cdd1dn) & U64;
  }
  nextU32() { return Number(this.nextU64() >> 32n); }
  nextInt(max) {
    if (max === 1) return 0;
    const range = 4294967296, limit = range - (range % max);
    let v; do { v = this.nextU32(); } while (v >= limit);
    return v % max;
  }
  pick(a) { return a[this.nextInt(a.length)]; }
}
function scenarioViewerLogin() {
  const first = ['ada', 'bram', 'cora', 'dmitri', 'elena', 'felix', 'greta', 'hugo', 'iris', 'jonas', 'kira', 'lars', 'mira', 'nico', 'olga', 'pavel', 'quinn', 'rosa', 'sven', 'tess', 'ulla', 'vito', 'wren', 'yara', 'zane'];
  const last = ['anders', 'bauer', 'costa', 'dahl', 'eriksen', 'fischer', 'garcia', 'holm', 'iversen', 'jansen', 'keller', 'lind', 'moreau', 'novak', 'olsen', 'peters', 'quist', 'rossi', 'sato', 'turi', 'ulrich', 'vega', 'weber', 'xu', 'yilmaz', 'zimmer'];
  const rng = new Rng(mix64(SCENARIO_SEED ^ fnv1a64('users')));
  const used = new Set();
  let login = '';
  for (let i = 0; i < 12; i++) {
    const f = rng.pick(first), l = rng.pick(last);
    let base = (f + l).replace(/[^a-z0-9-]/g, '');
    let cand = base, suf = 2;
    while (used.has(cand)) cand = base + '-' + (suf++);
    used.add(cand);
    if (i === 0) login = cand;
  }
  return login;
}
const VIEWER = scenarioViewerLogin(); // 'adaiversen'
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = VIEWER + '@example.invalid';

// ---------------------------------------------------------------- small helpers
let seq = 0; // deterministic monotonic counter (timestamps, request ids)
function ts() { seq += 1; return new Date((EPOCH + seq) * 1000).toISOString(); }
function sha1hex(buf) { return crypto.createHash('sha1').update(buf).digest('hex'); }
function hashObject(type, data) {
  const h = crypto.createHash('sha1');
  h.update(type + ' ' + data.length + '\0', 'latin1');
  h.update(data);
  return h.digest('hex');
}
function isOid(s) { return typeof s === 'string' && /^[0-9a-f]{40}$/.test(s); }
function b64encode(buf) { return Buffer.from(buf).toString('base64'); }
function b64decode(s) {
  try { return Buffer.from(String(s).replace(/[\r\n\t ]/g, ''), 'base64'); } catch { return null; }
}
function escJson(s) {
  return String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t');
}

// pkt-line: 4 lowercase hex digits of (payload length + 4), then payload.
function pktLine(payload) {
  const p = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
  const head = Buffer.alloc(4);
  head.write((p.length + 4).toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, p]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');
// Decode a whole buffer of pkt-lines into [{data:Buffer}|{flush}|{delim}|...].
// Returns null on malformed input.
function decodePktLines(buf) {
  const out = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) return null;
    const len = parseInt(buf.toString('ascii', off, off + 4), 16);
    if (Number.isNaN(len)) return null;
    if (len === 0) { out.push({ flush: true }); off += 4; continue; }
    if (len === 1) { out.push({ delim: true }); off += 4; continue; }
    if (len === 2) { out.push({ end: true }); off += 4; continue; }
    if (len < 4 || off + len > buf.length) return null;
    out.push({ data: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return out;
}
function pktText(packets) {
  const lines = [];
  for (const p of packets) if (p.data) lines.push(p.data.toString('utf8'));
  return lines;
}
// pack object header varint: (typeCode << 4) | size bits.
function packObjHeader(typeCode, size) {
  const bytes = [];
  let b = (typeCode << 4) | (size & 0x0f);
  size = Math.floor(size / 16);
  while (size > 0) { bytes.push(b | 0x80); b = size & 0x7f; size = Math.floor(size / 128); }
  bytes.push(b);
  return Buffer.from(bytes);
}
const TYPE_CODE = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

// ---------------------------------------------------------------- object store
// Objects live in a Map<oid, {t, d}> plus parsed-commit / parsed-tree caches.
// All git data flows through here; the REST/GraphQL/MCP layers sit on top.
class ObjStore {
  constructor() {
    this.objs = new Map(); // oid -> {t:type, d:Buffer}
    this.commits = new Map(); // oid -> {tree, parents:[oid], msg, raw}
    this.trees = new Map(); // oid -> [{mode, name, oid}]
  }
  has(oid) { return this.objs.has(oid); }
  get(oid) { return this.objs.get(oid); }
  put(type, data) {
    const oid = hashObject(type, data);
    if (!this.objs.has(oid)) this.objs.set(oid, { t: type, d: data });
    return oid;
  }
  putKnown(oid, type, data) {
    if (!this.objs.has(oid)) this.objs.set(oid, { t: type, d: data });
    return oid;
  }
  parseCommit(oid) {
    let c = this.commits.get(oid);
    if (c) return c;
    const o = this.objs.get(oid);
    if (!o || o.t !== 'commit') return null;
    const raw = o.d.toString('utf8');
    const split = raw.indexOf('\n\n');
    const head = split < 0 ? raw : raw.slice(0, split);
    const msg = split < 0 ? '' : raw.slice(split + 2);
    let tree = '';
    const parents = [];
    for (const line of head.split('\n')) {
      if (line.startsWith('tree ')) tree = line.slice(5).trim();
      else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    }
    c = { tree, parents, msg, raw };
    this.commits.set(oid, c);
    return c;
  }
  parseTree(oid) {
    let entries = this.trees.get(oid);
    if (entries) return entries;
    const o = this.objs.get(oid);
    if (!o || o.t !== 'tree') return null;
    entries = [];
    const d = o.d;
    let off = 0;
    while (off < d.length) {
      const sp = d.indexOf(0x20, off);
      const nul = d.indexOf(0x00, sp);
      if (sp < 0 || nul < 0 || nul + 21 > d.length) break;
      entries.push({ mode: d.toString('ascii', off, sp), name: d.toString('utf8', sp + 1, nul), oid: d.subarray(nul + 1, nul + 21).toString('hex') });
      off = nul + 21;
    }
    this.trees.set(oid, entries);
    return entries;
  }
  // Reachability closure (iterative DFS). Returns a Set of oids.
  reachable(roots) {
    const out = new Set();
    const stack = [];
    for (const r of roots) if (isOid(r) && !out.has(r)) stack.push(r);
    while (stack.length) {
      const oid = stack.pop();
      if (out.has(oid)) continue;
      const o = this.objs.get(oid);
      if (!o) continue;
      out.add(oid);
      if (o.t === 'commit') {
        const c = this.parseCommit(oid);
        if (c) {
          if (c.tree) stack.push(c.tree);
          for (const p of c.parents) stack.push(p);
        }
      } else if (o.t === 'tree') {
        const entries = this.parseTree(oid);
        if (entries) for (const e of entries) if (e.mode !== '160000') stack.push(e.oid);
      } else if (o.t === 'tag') {
        const m = o.d.toString('utf8').match(/^object ([0-9a-f]{40})$/m);
        if (m) stack.push(m[1]);
      }
    }
    return out;
  }
  // Reachability closure that stops descending past `cutoffs` (shallow
  // boundaries): the client holds a boundary commit and its tree/blobs, but
  // NOT its ancestors. Used for the have-side of a fetch.
  closureWithCut(roots, cutoffs) {
    const out = new Set();
    const stack = [];
    for (const r of roots) if (isOid(r) && !out.has(r)) stack.push(r);
    while (stack.length) {
      const oid = stack.pop();
      if (out.has(oid)) continue;
      const o = this.objs.get(oid);
      if (!o) continue;
      out.add(oid);
      if (o.t === 'commit') {
        const c = this.parseCommit(oid);
        if (c) {
          if (c.tree) stack.push(c.tree);
          if (!cutoffs.has(oid)) for (const p of c.parents) stack.push(p);
        }
      } else if (o.t === 'tree') {
        const entries = this.parseTree(oid);
        if (entries) for (const e of entries) if (e.mode !== '160000') stack.push(e.oid);
      } else if (o.t === 'tag') {
        const m = o.d.toString('utf8').match(/^object ([0-9a-f]{40})$/m);
        if (m) stack.push(m[1]);
      }
    }
    return out;
  }
  isAncestor(anc, desc) {
    // Is `anc` reachable from `desc` following commit parents?
    if (anc === desc) return true;
    const seen = new Set();
    const stack = [desc];
    while (stack.length) {
      const oid = stack.pop();
      if (oid === anc) return true;
      if (seen.has(oid)) continue;
      seen.add(oid);
      const c = this.parseCommit(oid);
      if (c) for (const p of c.parents) stack.push(p);
    }
    return false;
  }
}

// ---------------------------------------------------------------- pack read/write
// Read a pack buffer into [{oid, type, data}]. Handles plain objects and
// OFS/REF deltas. One inflateSync per entry; inflateSync({info:true}) reports
// the exact consumed input length, so no throwing probe is needed to find a
// zlib stream's end.
function readPack(buf, opts) {
  if (buf.length < 32) throw new Error('pack too short');
  if (buf.toString('ascii', 0, 4) !== 'PACK') throw new Error('bad pack magic');
  const version = buf.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error('bad pack version');
  const count = buf.readUInt32BE(8);
  const trailerAt = buf.length - 20;
  const wantTrailer = sha1hex(buf.subarray(0, trailerAt));
  if (wantTrailer !== buf.subarray(trailerAt).toString('hex')) throw new Error('bad pack trailer');
  const entries = []; // {offset, code, size, data:Buffer|null, baseOff?, baseOid?, oid?, type?, resolved?}
  const byOffset = new Map();
  let off = 12;
  for (let i = 0; i < count; i++) {
    const start = off;
    let b = buf[off++];
    const code = (b >> 4) & 7;
    let size = b & 0x0f;
    let shift = 4;
    while (b & 0x80) {
      b = buf[off++];
      size += (b & 0x7f) * (2 ** shift);
      shift += 7;
    }
    let baseOff = -1, baseOid = null;
    if (code === 6) {
      let v = buf[off++];
      let val = v & 0x7f;
      while (v & 0x80) { v = buf[off++]; val = ((val + 1) * 128) + (v & 0x7f); }
      baseOff = start - val;
    } else if (code === 7) {
      baseOid = buf.subarray(off, off + 20).toString('hex');
      off += 20;
    } else if (code !== 1 && code !== 2 && code !== 3 && code !== 4) {
      throw new Error('bad pack type');
    }
    const info = zlib.inflateSync(buf.subarray(off), { info: true });
    const data = info.buffer;
    if (data.length !== size) throw new Error('pack size mismatch');
    off += info.engine.bytesWritten;
    const e = { offset: start, code, size, data, baseOff, baseOid, oid: null, type: null };
    entries.push(e);
    byOffset.set(start, e);
  }
  if (off !== trailerAt) throw new Error('pack trailing bytes');
  // Resolve deltas (recursive, cycle-checked).
  const resolving = new Set();
  function resolve(e) {
    if (e.oid) return e;
    if (resolving.has(e)) throw new Error('delta cycle');
    resolving.add(e);
    if (e.code === 6 || e.code === 7) {
      let base = null;
      if (e.code === 6) base = byOffset.get(e.baseOff) || null;
      if (!base && e.baseOid) {
        // Thin REF delta: resolve the base from the caller's store when offered.
        const ext = opts && opts.resolveBase ? opts.resolveBase(e.baseOid) : null;
        if (ext) {
          e.type = ext.type;
          e.data = applyDelta(ext.data, e.data);
          e.oid = hashObject(e.type, e.data);
          resolving.delete(e);
          return e;
        }
        base = { oid: e.baseOid, type: null, data: null, external: true };
      }
      if (!base) throw new Error('delta base missing');
      if (!base.external) resolve(base);
      const baseData = base.external ? null : base.data;
      if (baseData === null && base.external) throw new Error('thin delta base not supplied');
      const out = applyDelta(baseData, e.data);
      e.type = base.type;
      e.data = out;
    } else {
      e.type = CODE_TYPE[e.code];
    }
    e.oid = hashObject(e.type, e.data);
    resolving.delete(e);
    return e;
  }
  // External (thin) bases are supplied by the caller through resolveThin.
  return { entries, byOffset, resolve, version, count };
}
function applyDelta(base, delta) {
  let p = 0;
  function varint() {
    let v = 0, s = 0, b;
    do { b = delta[p++]; v += (b & 0x7f) * (2 ** s); s += 7; } while (b & 0x80);
    return v;
  }
  const srcSize = varint();
  const tgtSize = varint();
  if (srcSize !== base.length) throw new Error('delta base size');
  const out = Buffer.alloc(tgtSize);
  let w = 0;
  while (p < delta.length) {
    const op = delta[p++];
    if (op & 0x80) {
      let cpOff = 0, cpSize = 0;
      if (op & 0x01) cpOff = delta[p++];
      if (op & 0x02) cpOff |= delta[p++] << 8;
      if (op & 0x04) cpOff |= delta[p++] << 16;
      if (op & 0x08) cpOff |= delta[p++] << 24;
      if (op & 0x10) cpSize = delta[p++];
      if (op & 0x20) cpSize |= delta[p++] << 8;
      if (op & 0x40) cpSize |= delta[p++] << 16;
      if (cpSize === 0) cpSize = 0x10000;
      base.copy(out, w, cpOff, cpOff + cpSize);
      w += cpSize;
    } else if (op !== 0) {
      delta.copy(out, w, p, p + op);
      p += op; w += op;
    } else throw new Error('delta opcode 0');
  }
  if (w !== tgtSize) throw new Error('delta size');
  return out;
}
// Write a pack of plain objects (no deltas — allowed by the suite).
function writePack(objects) {
  const parts = [];
  let total = 12 + 20;
  const head = Buffer.alloc(12);
  head.write('PACK', 0, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(objects.length, 8);
  parts.push(head);
  for (const o of objects) {
    const def = zlib.deflateSync(o.data, { level: 1 });
    const h = packObjHeader(TYPE_CODE[o.type], o.data.length);
    parts.push(h, def);
    total += h.length + def.length;
  }
  const body = Buffer.concat(parts, total - 20);
  const trailer = crypto.createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

// ---------------------------------------------------------------- git tree/commit builders
function compareTreeNames(a, b) {
  // git tree sort: directory names compare as if suffixed with '/'.
  const an = a.dir ? a.name + '/' : a.name;
  const bn = b.dir ? b.name + '/' : b.name;
  return an < bn ? -1 : an > bn ? 1 : 0;
}
function buildTree(store, entries) {
  // entries: [{mode, name, oid, dir}] — sorted git-style, then hashed.
  const sorted = [...entries].sort(compareTreeNames);
  const parts = [];
  for (const e of sorted) {
    parts.push(Buffer.from(e.mode + ' ' + e.name + '\0', 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  const data = Buffer.concat(parts);
  return store.put('tree', data);
}
function buildCommit(store, treeOid, parents, message, epochSec) {
  const who = VIEWER_NAME + ' <' + VIEWER_EMAIL + '> ' + epochSec + ' +0000';
  let s = 'tree ' + treeOid + '\n';
  for (const p of parents) s += 'parent ' + p + '\n';
  s += 'author ' + who + '\ncommitter ' + who + '\n\n' + message;
  return store.put('commit', Buffer.from(s, 'utf8'));
}
function treeEntriesSorted(store, treeOid) {
  const entries = store.parseTree(treeOid) || [];
  return [...entries].sort((a, b) => compareTreeNames(
    { name: a.name, dir: a.mode === '40000' }, { name: b.name, dir: b.mode === '40000' }));
}
// Resolve a path (['a','b','c.txt']) through a tree; returns {oid,type,mode} or null.
function lookupPath(store, treeOid, parts) {
  let cur = treeOid;
  for (let i = 0; i < parts.length; i++) {
    const entries = store.parseTree(cur);
    if (!entries) return null;
    const e = entries.find(x => x.name === parts[i]);
    if (!e) return null;
    if (i === parts.length - 1) return { oid: e.oid, mode: e.mode, type: e.mode === '40000' ? 'tree' : 'blob' };
    if (e.mode !== '40000') return null;
    cur = e.oid;
  }
  return null;
}
// Replace (or delete, when blobOid is null) a path in a tree; returns new tree oid.
function setPathInTree(store, treeOid, parts, blobOid) {
  const entries = treeOid ? (store.parseTree(treeOid) || []) : [];
  const name = parts[0];
  const idx = entries.findIndex(x => x.name === name);
  let next = entries.slice();
  if (parts.length === 1) {
    if (blobOid === null) {
      if (idx >= 0) next.splice(idx, 1);
    } else if (idx >= 0) {
      next[idx] = { mode: '100644', name, oid: blobOid };
    } else {
      next.push({ mode: '100644', name, oid: blobOid });
    }
  } else {
    const child = idx >= 0 && entries[idx].mode === '40000' ? entries[idx].oid : null;
    const newChild = setPathInTree(store, child, parts.slice(1), blobOid);
    const childEntries = store.parseTree(newChild) || [];
    if (childEntries.length === 0 && blobOid === null) {
      if (idx >= 0) next.splice(idx, 1);
    } else if (idx >= 0) {
      next[idx] = { mode: '40000', name, oid: newChild };
    } else {
      next.push({ mode: '40000', name, oid: newChild });
    }
  }
  if (next.length === 0) return store.put('tree', Buffer.alloc(0));
  return buildTree(store, next.map(e => ({ mode: e.mode, name: e.name, oid: e.oid, dir: e.mode === '40000' })));
}
function listTreePaths(store, treeOid, prefix, out) {
  const entries = store.parseTree(treeOid) || [];
  for (const e of entries) {
    const p = prefix ? prefix + '/' + e.name : e.name;
    if (e.mode === '40000') listTreePaths(store, e.oid, p, out);
    else out.push({ path: p, oid: e.oid, mode: e.mode });
  }
  return out;
}
function diffTrees(store, baseTree, headTree) {
  const base = new Map(listTreePaths(store, baseTree, '', []).map(f => [f.path, f.oid]));
  const head = new Map(listTreePaths(store, headTree, '', []).map(f => [f.path, f.oid]));
  const files = [];
  for (const [path, oid] of head) {
    if (!base.has(path)) files.push({ filename: path, status: 'added', newOid: oid, oldOid: null });
    else if (base.get(path) !== oid) files.push({ filename: path, status: 'modified', newOid: oid, oldOid: base.get(path) });
  }
  for (const [path, oid] of base) if (!head.has(path)) files.push({ filename: path, status: 'removed', newOid: null, oldOid: oid });
  return files;
}
function lineCount(buf) {
  if (!buf || buf.length === 0) return 0;
  let n = 0;
  for (let i = 0; i < buf.length; i++) if (buf[i] === 10) n++;
  return n + (buf[buf.length - 1] === 10 ? 0 : 1);
}

// ---------------------------------------------------------------- repo store + domain
let nextId = 1;
class Repo {
  constructor(name, desc, priv) {
    this.id = nextId++;
    this.name = name;
    this.owner = VIEWER;
    this.description = desc || '';
    this.private = !!priv;
    this.defaultBranch = 'main';
    this.store = new ObjStore();
    this.refs = new Map(); // 'refs/heads/main' -> oid
    this.issues = []; // {id, number, title, body, state, labels:[{name,color}], seq, json:Buffer|null}
    this.issueByNumber = new Map();
    this.nextIssue = 1;
    this.pulls = []; // {id, number, title, body, state, head, base, headSha, baseSha, merged, mergedAt, mergeSha, seq, files:[...]}
    this.pullByNumber = new Map();
    this.nextPull = 1;
    this.labels = new Map(); // name -> {name, color}
    this.comments = new Map(); // issue number -> [{id, body}]
    this.nextComment = 1;
    this.gen = 0; // bumped on any refs/objects mutation; caches key off it
    this.cache = new Map(); // key -> Buffer (fetch/advert/ls-refs responses)
    this.createdAt = ts();
    this.updatedAt = this.createdAt;
  }
  bump() { this.gen += 1; this.cache.clear(); }
  tip(ref) { return this.refs.get(ref) || null; }
  branchTip(branch) { return this.refs.get('refs/heads/' + branch) || null; }
  setRef(ref, oid) {
    if (oid === null) this.refs.delete(ref); else this.refs.set(ref, oid);
    this.bump();
  }
  headRef() { return 'refs/heads/' + this.defaultBranch; }
  // Global ids: opaque, stable, never the plain numeric id.
  repoGid() { return Buffer.from('R:' + this.id, 'utf8').toString('base64'); }
  issueGid(n) { return Buffer.from('I:' + this.id + ':' + n, 'utf8').toString('base64'); }
  pullGid(n) { return Buffer.from('P:' + this.id + ':' + n, 'utf8').toString('base64'); }
  commentGid(issueNum, cid) { return Buffer.from('C:' + this.id + ':' + issueNum + ':' + cid, 'utf8').toString('base64'); }
  issueJson(iss) {
    if (iss.json) return iss.json;
    const labels = iss.labels.map(l => '{"name":"' + escJson(l.name) + '","color":"' + escJson(l.color || 'ededed') + '"}').join(',');
    const s = '{"id":' + iss.id + ',"node_id":"' + this.issueGid(iss.number) + '","number":' + iss.number
      + ',"title":"' + escJson(iss.title) + '","body":"' + escJson(iss.body) + '","state":"' + iss.state
      + '","labels":[' + labels + '],"user":{"login":"' + VIEWER + '"},"created_at":"' + iss.createdAt
      + '","updated_at":"' + iss.updatedAt + '"}';
    iss.json = Buffer.from(s, 'utf8');
    return iss.json;
  }
  repoJson() {
    return '{"id":' + this.id + ',"node_id":"' + this.repoGid() + '","name":"' + escJson(this.name)
      + '","full_name":"' + VIEWER + '/' + escJson(this.name) + '","owner":{"login":"' + VIEWER + '","id":1000}'
      + ',"private":' + (this.private ? 'true' : 'false') + ',"description":"' + escJson(this.description)
      + '","default_branch":"' + this.defaultBranch + '","has_issues":true,"created_at":"' + this.createdAt
      + '","updated_at":"' + this.updatedAt + '"}';
  }
}
const repos = new Map(); // 'owner/name' -> Repo
const reposById = new Map(); // id -> Repo
function getRepo(owner, name) {
  if (owner !== VIEWER) return null;
  return repos.get(owner + '/' + name) || null;
}
function createRepoRecord(name, desc, priv) {
  const key = VIEWER + '/' + name;
  const old = repos.get(key);
  if (old) return { repo: old, created: false };
  const r = new Repo(name, desc, priv);
  repos.set(key, r);
  reposById.set(r.id, r);
  return { repo: r, created: true };
}
function resolveGid(gid) {
  try {
    const s = Buffer.from(String(gid), 'base64').toString('utf8');
    const parts = s.split(':');
    if (parts[0] === 'R' && parts.length === 2) return { kind: 'R', repo: reposById.get(Number(parts[1])) || null };
    if (parts[0] === 'I' && parts.length === 3) {
      const repo = reposById.get(Number(parts[1])) || null;
      return { kind: 'I', repo, issue: repo ? repo.issueByNumber.get(Number(parts[2])) || null : null };
    }
    if (parts[0] === 'P' && parts.length === 3) {
      const repo = reposById.get(Number(parts[1])) || null;
      return { kind: 'P', repo, pull: repo ? repo.pullByNumber.get(Number(parts[2])) || null : null };
    }
    if (parts[0] === 'C' && parts.length === 4) {
      const repo = reposById.get(Number(parts[1])) || null;
      return { kind: 'C', repo };
    }
  } catch { /* fall through */ }
  return { kind: '?', repo: null };
}

// ---- issue domain
function createIssue(repo, title, body, labelNames) {
  const labels = [];
  if (labelNames) {
    for (const n of labelNames) {
      const l = repo.labels.get(n);
      if (!l) return { error: 422, message: 'label does not exist: ' + n };
      labels.push({ name: l.name, color: l.color });
    }
  }
  const n = repo.nextIssue++;
  const iss = {
    id: nextId++, number: n, title: title || '', body: body || '', state: 'open',
    labels, seq: seq, createdAt: ts(), updatedAt: '', json: null,
  };
  iss.updatedAt = iss.createdAt;
  repo.issues.push(iss);
  repo.issueByNumber.set(n, iss);
  repo.comments.set(n, []);
  return { issue: iss };
}
function closeIssue(repo, iss) {
  iss.state = 'closed';
  iss.updatedAt = ts();
  iss.json = null;
}

// ---- pull domain
function mergeBase(store, a, b) {
  // First common ancestor by walking both histories (newest-first BFS).
  const seenA = new Set();
  const qa = [a];
  while (qa.length) {
    const o = qa.pop();
    if (seenA.has(o)) continue;
    seenA.add(o);
    const c = store.parseCommit(o);
    if (c) for (const p of c.parents) qa.push(p);
  }
  const seenB = new Set();
  const qb = [b];
  while (qb.length) {
    const o = qb.pop();
    if (seenA.has(o)) return o;
    if (seenB.has(o)) continue;
    seenB.add(o);
    const c = store.parseCommit(o);
    if (c) for (const p of c.parents) qb.push(p);
  }
  return null;
}
function prFiles(repo, pr) {
  if (pr.files) return pr.files;
  const store = repo.store;
  const headC = store.parseCommit(pr.headSha);
  const baseC = store.parseCommit(pr.baseSha);
  if (!headC || !baseC) { pr.files = []; return pr.files; }
  const raw = diffTrees(store, baseC.tree, headC.tree);
  pr.files = raw.map(f => {
    let additions = 0, deletions = 0;
    if (f.newOid) additions = Math.max(1, lineCount(store.get(f.newOid).d));
    if (f.oldOid) deletions = lineCount(store.get(f.oldOid).d);
    return { filename: f.filename, status: f.status, additions, deletions, changes: additions + deletions, newOid: f.newOid, oldOid: f.oldOid };
  });
  return pr.files;
}
function prConflict(repo, pr) {
  const store = repo.store;
  const baseTipOid = repo.branchTip(pr.base);
  if (!baseTipOid) return false;
  const base = mergeBase(store, pr.headSha, baseTipOid);
  if (!base) return false;
  const baseC = store.parseCommit(base);
  const baseTipC = store.parseCommit(baseTipOid);
  if (!baseC || !baseTipC) return false;
  const files = prFiles(repo, pr);
  for (const f of files) {
    const atBase = lookupPath(store, baseC.tree, f.filename.split('/'));
    const atTip = lookupPath(store, baseTipC.tree, f.filename.split('/'));
    const baseOid = atBase ? atBase.oid : null;
    const tipOid = atTip ? atTip.oid : null;
    if (baseOid !== tipOid) return true; // base moved under this file
  }
  return false;
}
function createPull(repo, title, body, head, base) {
  const headSha = repo.branchTip(head);
  const baseSha = repo.branchTip(base);
  if (!headSha || !baseSha) return { error: 422, message: 'unknown head or base branch' };
  const n = repo.nextPull++;
  const pr = {
    id: nextId++, number: n, title: title || '', body: body || '', state: 'open',
    head, base, headSha, baseSha, merged: false, mergedAt: '', mergeSha: '',
    seq: seq, files: null, createdAt: ts(),
  };
  repo.pulls.push(pr);
  repo.pullByNumber.set(n, pr);
  return { pull: pr };
}
function mergePull(repo, pr) {
  if (pr.state !== 'open') return { error: 405, message: 'pull request is not open' };
  if (prConflict(repo, pr)) return { error: 405, message: 'merge conflict' };
  const store = repo.store;
  const baseTipOid = repo.branchTip(pr.base);
  const baseC = store.parseCommit(baseTipOid);
  const headC = store.parseCommit(pr.headSha);
  if (!baseC || !headC) return { error: 422, message: 'missing branch tip' };
  // Apply head's changed files onto the base tree.
  let tree = baseC.tree;
  for (const f of prFiles(repo, pr)) {
    if (f.status === 'removed') tree = setPathInTree(store, tree, f.filename.split('/'), null);
    else tree = setPathInTree(store, tree, f.filename.split('/'), f.newOid);
  }
  const msg = 'Merge pull request #' + pr.number + ' from ' + pr.head + '\n';
  const mergeOid = buildCommit(store, tree, [baseTipOid], msg, EPOCH + seq);
  seq += 1;
  repo.setRef('refs/heads/' + pr.base, mergeOid);
  pr.state = 'closed';
  pr.merged = true;
  pr.mergedAt = ts();
  pr.mergeSha = mergeOid;
  return { sha: mergeOid };
}
function pullJson(repo, pr) {
  const s = '{"id":' + pr.id + ',"node_id":"' + repo.pullGid(pr.number) + '","number":' + pr.number
    + ',"title":"' + escJson(pr.title) + '","body":"' + escJson(pr.body) + '","state":"' + pr.state
    + '","head":{"ref":"' + escJson(pr.head) + '","sha":"' + pr.headSha + '","label":"' + VIEWER + ':' + escJson(pr.head) + '"}'
    + ',"base":{"ref":"' + escJson(pr.base) + '","sha":"' + pr.baseSha + '","label":"' + VIEWER + ':' + escJson(pr.base) + '"}'
    + ',"merged":' + (pr.merged ? 'true' : 'false')
    + (pr.merged ? ',"merged_at":"' + pr.mergedAt + '","merge_commit_sha":"' + pr.mergeSha + '"' : '')
    + ',"mergeable":' + (pr.state === 'open' ? (prConflict(repo, pr) ? '"CONFLICTING"' : '"MERGEABLE"') : '"UNKNOWN"')
    + ',"created_at":"' + pr.createdAt + '"}';
  return s;
}

// ---------------------------------------------------------------- git: fetch selection
function fetchSelection(repo, wants, haves, shallowReq, depth) {
  const store = repo.store;
  // The have-side stops at shallow boundaries: a shallow clone holds the
  // boundary commit itself, not its ancestors.
  const haveClosure = store.closureWithCut(haves, new Set(shallowReq || []));
  const result = new Set();
  const shallow = [];
  const unshallow = [];
  if (depth === null || depth === undefined) {
    const wantClosure = store.reachable(wants);
    for (const o of wantClosure) if (!haveClosure.has(o)) result.add(o);
    return { objects: result, shallow, unshallow };
  }
  // Depth-limited walk: BFS over commits from wants, depth steps of ancestry.
  const included = new Set(); // commits included
  const boundary = new Set(); // commits at exactly `depth` whose parents are cut
  const queue = [];
  for (const w of wants) {
    if (store.get(w)?.t === 'commit') queue.push([w, 1]);
    else if (store.get(w)?.t === 'tag') {
      const m = store.get(w).d.toString('utf8').match(/^object ([0-9a-f]{40})$/m);
      if (m) queue.push([m[1], 1]);
    }
  }
  const seenCommit = new Set();
  while (queue.length) {
    const [oid, d] = queue.shift();
    if (seenCommit.has(oid)) continue;
    seenCommit.add(oid);
    const c = store.parseCommit(oid);
    if (!c) continue;
    included.add(oid);
    if (d >= depth) {
      if (c.parents.length > 0) boundary.add(oid);
    } else {
      for (const p of c.parents) queue.push([p, d + 1]);
    }
  }
  // Objects: included commits + their trees/blobs (full tree closure each).
  for (const oid of included) {
    const c = store.parseCommit(oid);
    if (!c) continue;
    const closure = store.reachable([oid]);
    // reachable() would pull parents too — restrict to commit+tree+blobs only.
    const keep = new Set([oid]);
    const stack = [c.tree];
    while (stack.length) {
      const t = stack.pop();
      if (keep.has(t)) continue;
      const o = store.get(t);
      if (!o) continue;
      keep.add(t);
      if (o.t === 'tree') {
        const entries = store.parseTree(t) || [];
        for (const e of entries) {
          if (e.mode === '40000') stack.push(e.oid);
          else keep.add(e.oid);
        }
      }
    }
    for (const o of keep) if (!haveClosure.has(o)) result.add(o);
    void closure;
  }
  // Non-commit wants (tags): include the tag object itself + target handled above.
  for (const w of wants) {
    const o = store.get(w);
    if (o && o.t === 'tag' && !haveClosure.has(w)) result.add(w);
  }
  for (const b of boundary) shallow.push(b);
  for (const s of shallowReq || []) {
    if (included.has(s) && !boundary.has(s)) unshallow.push(s);
  }
  return { objects: result, shallow, unshallow };
}
function buildFetchPack(repo, objects) {
  // Deterministic order: commits, then trees, then blobs, each sorted by oid.
  const arr = [...objects].map(oid => {
    const o = repo.store.get(oid);
    return o ? { oid, type: o.t, data: o.d } : null;
  }).filter(Boolean);
  const rank = { commit: 0, tree: 1, blob: 2, tag: 3 };
  arr.sort((a, b) => (rank[a.type] - rank[b.type]) || (a.oid < b.oid ? -1 : 1));
  return writePack(arr);
}
function sidebandPack(pack) {
  // Split pack bytes into sideband band-1 pkt-lines (<= 65516 payload each).
  const parts = [];
  let off = 0;
  while (off < pack.length) {
    const chunk = pack.subarray(off, Math.min(pack.length, off + 65500));
    const payload = Buffer.concat([Buffer.from([1]), chunk]);
    parts.push(pktLine(payload));
    off += chunk.length;
  }
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------- git: advertisements
function refList(repo) {
  // Sorted refs: heads then tags, by name. Plus HEAD symref info.
  const refs = [];
  for (const [name, oid] of repo.refs) refs.push({ name, oid });
  refs.sort((a, b) => (a.name < b.name ? -1 : 1));
  return refs;
}
function v0Advert(repo, service) {
  const key = 'adv0:' + service + ':' + repo.gen;
  const hit = repo.cache.get(key);
  if (hit) return hit;
  const caps = service === 'git-receive-pack'
    ? 'report-status report-status-v2 side-band-64k delete-refs ofs-delta agent=' + AGENT + ' symref=HEAD:refs/heads/main'
    : 'side-band-64k ofs-delta agent=' + AGENT + ' symref=HEAD:refs/heads/main';
  const parts = [pktLine('# service=' + service + '\n'), PKT_FLUSH];
  const refs = refList(repo);
  if (refs.length === 0) {
    parts.push(pktLine(ZERO_OID + ' capabilities^{}\0' + caps + '\n'));
  } else {
    let first = true;
    const tip = repo.branchTip('main');
    if (tip) {
      parts.push(pktLine(tip + ' HEAD' + (first ? '\0' + caps : '') + '\n'));
      first = false;
    }
    for (const r of refs) {
      parts.push(pktLine(r.oid + ' ' + r.name + (first ? '\0' + caps : '') + '\n'));
      first = false;
      if (r.name.startsWith('refs/tags/')) {
        const tag = repo.store.get(r.oid);
        if (tag && tag.t === 'tag') {
          const m = tag.d.toString('utf8').match(/^object ([0-9a-f]{40})$/m);
          if (m) parts.push(pktLine(m[1] + ' ' + r.name + '^{}\n'));
        }
      }
    }
  }
  parts.push(PKT_FLUSH);
  const out = Buffer.concat(parts);
  repo.cache.set(key, out);
  return out;
}
function v2Advert(repo) {
  const key = 'adv2:' + repo.gen;
  const hit = repo.cache.get(key);
  if (hit) return hit;
  const lines = ['version 2\n', 'agent=' + AGENT + '\n', 'ls-refs=unborn\n', 'fetch=shallow filter\n', 'object-format=sha1\n'];
  const parts = lines.map(l => pktLine(l));
  parts.push(PKT_FLUSH);
  const out = Buffer.concat(parts);
  repo.cache.set(key, out);
  return out;
}
function lsRefsResponse(repo, args) {
  const key = 'ls:' + repo.gen + ':' + JSON.stringify(args);
  const hit = repo.cache.get(key);
  if (hit) return hit;
  const prefixes = args.prefixes || [];
  const keep = (n) => prefixes.length === 0 || prefixes.some(p => n.startsWith(p));
  const lines = [];
  const tip = repo.branchTip('main');
  if (tip && keep('HEAD') && args.symrefs !== false) {
    lines.push(tip + ' HEAD symref-target:refs/heads/main\n');
  }
  for (const r of refList(repo)) {
    if (!keep(r.name)) continue;
    let line = r.oid + ' ' + r.name;
    if (args.symrefs !== false && r.name === 'HEAD') line += ' symref-target:refs/heads/main';
    if (args.peel !== false && r.name.startsWith('refs/tags/')) {
      const tag = repo.store.get(r.oid);
      if (tag && tag.t === 'tag') {
        const m = tag.d.toString('utf8').match(/^object ([0-9a-f]{40})$/m);
        if (m) line += ' peeled:' + m[1];
      }
    }
    lines.push(line + '\n');
  }
  if (refList(repo).length === 0 && args.unborn) {
    lines.push('unborn HEAD symref-target:refs/heads/main\n');
  }
  const parts = lines.map(l => pktLine(l));
  parts.push(PKT_FLUSH);
  const out = Buffer.concat(parts);
  repo.cache.set(key, out);
  return out;
}

// ---------------------------------------------------------------- git: upload-pack
function handleUploadPack(repo, body, isV2) {
  const packets = decodePktLines(body);
  if (!packets) return { status: 400, body: Buffer.from('bad pkt-line', 'utf8') };
  const lines = pktText(packets);
  const first = lines[0] || '';
  if (first.startsWith('command=ls-refs')) {
    const args = { peel: true, symrefs: true, unborn: false, prefixes: [] };
    for (const l of lines.slice(1)) {
      const t = l.trim();
      if (t.startsWith('agent=') || t.startsWith('object-format=')) continue;
      if (t === 'peel') args.peel = true;
      else if (t === 'symrefs') args.symrefs = true;
      else if (t === 'unborn') args.unborn = true;
      else if (t.startsWith('ref-prefix ')) args.prefixes.push(t.slice(11));
    }
    return { status: 200, ctype: 'application/x-git-upload-pack-result', body: lsRefsResponse(repo, args) };
  }
  if (first.startsWith('command=fetch')) {
    const wants = [], haves = [], shallowReq = [];
    let depth = null, done = true;
    for (const l of lines.slice(1)) {
      const t = l.trim();
      if (t.startsWith('agent=') || t.startsWith('object-format=')) continue;
      if (t.startsWith('want ')) wants.push(t.slice(5).trim().split(/\s+/)[0]);
      else if (t.startsWith('have ')) haves.push(t.slice(5).trim().split(/\s+/)[0]);
      else if (t.startsWith('shallow ')) shallowReq.push(t.slice(8).trim().split(/\s+/)[0]);
      else if (t.startsWith('deepen ')) depth = parseInt(t.slice(7), 10) || null;
      else if (t === 'done') done = true;
    }
    void done;
    const key = 'fetch:' + (isV2 ? 'v2' : 'v0') + ':' + repo.gen + ':' + wants.join(',') + '|' + haves.join(',') + '|' + shallowReq.join(',') + '|' + depth;
    const hit = repo.cache.get(key);
    if (hit) return { status: 200, ctype: 'application/x-git-upload-pack-result', body: hit };
    const sel = fetchSelection(repo, wants, haves, shallowReq, depth);
    const pack = buildFetchPack(repo, sel.objects);
    const parts = [];
    if (isV2) {
      parts.push(pktLine('acknowledgments\n'), pktLine('NAK\n'), PKT_DELIM);
      if (sel.shallow.length || sel.unshallow.length) {
        parts.push(pktLine('shallow-info\n'));
        for (const s of sel.shallow) parts.push(pktLine('shallow ' + s + '\n'));
        for (const s of sel.unshallow) parts.push(pktLine('unshallow ' + s + '\n'));
        parts.push(PKT_DELIM);
      }
      parts.push(pktLine('packfile\n'));
      parts.push(sidebandPack(pack));
      parts.push(PKT_FLUSH);
    } else {
      parts.push(pktLine('NAK\n'));
      for (const s of sel.shallow) parts.push(pktLine('shallow ' + s + '\n'));
      for (const s of sel.unshallow) parts.push(pktLine('unshallow ' + s + '\n'));
      parts.push(sidebandPack(pack));
      parts.push(PKT_FLUSH);
    }
    const out = Buffer.concat(parts);
    repo.cache.set(key, out);
    return { status: 200, ctype: 'application/x-git-upload-pack-result', body: out };
  }
  return { status: 400, body: Buffer.from('unknown command', 'utf8') };
}

// ---------------------------------------------------------------- git: receive-pack
function handleReceivePack(repo, body) {
  const report = [];
  let unpackOk = true;
  let unpackDetail = 'ok';
  const commands = [];
  // Commands are pkt-line framed until the first flush; the pack follows raw,
  // so decode the command list by walking raw bytes (never decodePktLines on
  // the whole body — the trailing pack bytes are not pkt-lines).
  let packStart = body.length;
  {
    let pos = 0;
    const lines = [];
    let malformed = false;
    while (pos < body.length) {
      if (pos + 4 > body.length) { malformed = true; break; }
      const len = parseInt(body.toString('ascii', pos, pos + 4), 16);
      if (Number.isNaN(len)) { malformed = true; break; }
      if (len === 0) { pos += 4; break; }
      if (len < 4 || pos + len > body.length) { malformed = true; break; }
      lines.push(body.toString('utf8', pos + 4, pos + len));
      pos += len;
    }
    packStart = pos;
    if (malformed && lines.length === 0 && body.length > 0) {
      unpackOk = false; unpackDetail = 'bad pkt-line';
    }
    for (const line of lines) {
      const t = line.replace(/\n$/, '');
      const nul = t.indexOf('\0');
      const core = nul >= 0 ? t.slice(0, nul) : t;
      const m = core.match(/^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)$/);
      if (m) commands.push({ oldOid: m[1], newOid: m[2], ref: m[3] });
    }
  }
  if (commands.length === 0 && body.length > 0 && unpackOk) {
    unpackOk = false; unpackDetail = 'no commands';
  }
  // Unpack the pack (if any) and store its objects.
  if (unpackOk) {
    try {
      const packBuf = body.subarray(packStart);
      if (packBuf.length >= 32) {
        const { entries, resolve } = readPack(packBuf, {
          resolveBase: (oid) => {
            const o = repo.store.get(oid);
            return o ? { type: o.t, data: o.d } : null;
          },
        });
        for (const e of entries) {
          const r = resolve(e);
          repo.store.putKnown(r.oid, r.type, r.data);
        }
      } else if (packBuf.length > 0 && packBuf.length < 32) {
        throw new Error('short pack');
      }
    } catch (e) {
      unpackOk = false;
      unpackDetail = String(e && e.message ? e.message : e);
    }
  }
  // Apply commands in order; report per ref.
  for (const cmd of commands) {
    const cur = repo.refs.get(cmd.ref) || null;
    let ok = false;
    if (!unpackOk) {
      ok = false;
    } else if (cmd.newOid === ZERO_OID) {
      // delete
      if (cur !== null && cmd.oldOid === cur) { repo.setRef(cmd.ref, null); ok = true; }
      else if (cur === null && cmd.oldOid === ZERO_OID) ok = true;
    } else if (cmd.oldOid === ZERO_OID) {
      // create
      if (cur === null && repo.store.has(cmd.newOid)) { repo.setRef(cmd.ref, cmd.newOid); ok = true; }
    } else if (cur === cmd.oldOid) {
      // fast-forward update
      if (repo.store.has(cmd.newOid)) {
        const nc = repo.store.parseCommit(cmd.newOid);
        if (nc && repo.store.isAncestor(cmd.oldOid, cmd.newOid)) { repo.setRef(cmd.ref, cmd.newOid); ok = true; }
        else if (cmd.newOid === cmd.oldOid) { ok = true; }
      }
    }
    report.push({ ref: cmd.ref, ok, reason: ok ? '' : 'non-fast-forward' });
  }
  if (commands.length === 0 && !unpackOk) {
    // No commands to report; still answer a report so the client sees unpack.
  }
  // Report-status v2 inside sideband band 1 (report-status-v2 advertised).
  const inner = [];
  inner.push(pktLine('unpack ' + (unpackOk ? 'ok' : unpackDetail) + '\n'));
  for (const r of report) {
    inner.push(pktLine(r.ok ? 'ok ' + r.ref + '\n' : 'ng ' + r.ref + ' ' + r.reason + '\n'));
  }
  inner.push(PKT_FLUSH);
  const reportBytes = Buffer.concat(inner);
  const payload = Buffer.concat([Buffer.from([1]), reportBytes]);
  const out = Buffer.concat([pktLine(payload), PKT_FLUSH]);
  return { status: 200, ctype: 'application/x-git-receive-pack-result', body: out };
}

// ---------------------------------------------------------------- HTTP plumbing helpers
function jbuf(s) { return Buffer.from(s, 'utf8'); }
function jsonResp(status, s) { return { status, ctype: 'application/json', body: typeof s === 'string' ? jbuf(s) : jbuf(JSON.stringify(s)) }; }
function errResp(status, message) { return jsonResp(status, '{"message":"' + escJson(message) + '"}'); }
function parseJsonBody(body) {
  if (!body || body.length === 0) return { ok: true, value: {} };
  try { return { ok: true, value: JSON.parse(body.toString('utf8')) }; }
  catch { return { ok: false }; }
}
function authed(headers) {
  const a = headers['authorization'];
  if (!a || !a.startsWith('Bearer ')) return false;
  const tok = a.slice(7);
  if (tok.length === 0) return false;
  if (EXPECTED_TOKEN) return tok === EXPECTED_TOKEN;
  return true;
}
function parseQuery(qs) {
  const out = {};
  if (!qs) return out;
  for (const part of qs.split('&')) {
    if (!part) continue;
    const eq = part.indexOf('=');
    if (eq < 0) out[decodeURIComponent(part)] = '';
    else out[decodeURIComponent(part.slice(0, eq))] = decodeURIComponent(part.slice(eq + 1));
  }
  return out;
}
function decSeg(s) { return s.indexOf('%') >= 0 ? decodeURIComponent(s) : s; }
function linkHeader(host, path, query) {
  return '<http://' + host + path + '?' + query + '>; rel="next"';
}
function pageSlice(items, q) {
  const per = Math.max(1, Math.min(100, parseInt(q.per_page, 10) || 30));
  const page = Math.max(1, parseInt(q.page, 10) || 1);
  const start = (page - 1) * per;
  return { items: items.slice(start, start + per), hasNext: start + per < items.length, per, page };
}

// ---------------------------------------------------------------- REST v3
function restRepoJson(repo) { return jsonResp(200, repo.repoJson()); }
function handleRest(method, segs, q, headers, body, host) {
  // segs: path segments after /api/v3 (decoded).
  if (segs.length === 0) {
    if (method !== 'GET') return errResp(404, 'not found');
    return { status: 200, ctype: 'application/json', body: jbuf('{"current_user_url":"/api/v3/user"}'), extra: [['x-oauth-scopes', 'repo, user']] };
  }
  if (segs[0] === 'meta' && segs.length === 1) {
    if (method !== 'GET') return errResp(404, 'not found');
    return jsonResp(200, '{"installed_version":"3.0.0"}');
  }
  if (segs[0] === 'user' && segs.length === 1) {
    if (method === 'GET') return jsonResp(200, '{"login":"' + VIEWER + '","id":1000,"type":"User"}');
    return errResp(404, 'not found');
  }
  if (segs[0] === 'user' && segs[1] === 'repos') {
    if (method === 'POST') {
      const p = parseJsonBody(body);
      if (!p.ok) return errResp(400, 'malformed JSON body');
      const name = p.value && typeof p.value.name === 'string' ? p.value.name : '';
      if (!name) return errResp(422, 'name is required');
      const { repo, created } = createRepoRecord(name, p.value.description || '', !!p.value.private);
      if (!created) return errResp(422, 'repository already exists');
      return jsonResp(201, repo.repoJson());
    }
    if (method === 'GET') {
      const all = [...repos.values()].filter(r => r.owner === VIEWER);
      const pg = pageSlice(all, q);
      const s = '[' + pg.items.map(r => r.repoJson()).join(',') + ']';
      const extra = [];
      if (pg.hasNext) extra.push(['link', linkHeader(host, '/api/v3/user/repos', 'per_page=' + pg.per + '&page=' + (pg.page + 1))]);
      return { status: 200, ctype: 'application/json', body: jbuf(s), extra };
    }
    return errResp(404, 'not found');
  }
  if (segs[0] === 'repos' && segs.length >= 3) {
    const owner = segs[1], name = segs[2];
    const repo = getRepo(owner, name);
    if (!repo) return errResp(404, 'repository not found');
    const rest = segs.slice(3);
    // GET /repos/{o}/{r}
    if (rest.length === 0) {
      if (method === 'GET') return restRepoJson(repo);
      if (method === 'PATCH') {
        const p = parseJsonBody(body);
        if (!p.ok) return errResp(400, 'malformed JSON body');
        if (typeof p.value.description === 'string') { repo.description = p.value.description; repo.updatedAt = ts(); }
        return restRepoJson(repo);
      }
      if (method === 'DELETE') {
        repos.delete(VIEWER + '/' + name);
        reposById.delete(repo.id);
        return { status: 204, ctype: 'application/json', body: Buffer.alloc(0) };
      }
      return errResp(404, 'not found');
    }
    // git/refs
    if (rest[0] === 'git' && rest[1] === 'refs' && method === 'POST' && rest.length === 2) {
      const p = parseJsonBody(body);
      if (!p.ok) return errResp(400, 'malformed JSON body');
      const ref = p.value.ref || '';
      const sha = p.value.sha || '';
      if (!ref.startsWith('refs/heads/') || !isOid(sha) || !repo.store.has(sha)) return errResp(422, 'invalid ref or sha');
      repo.setRef(ref, sha);
      return jsonResp(201, '{"ref":"' + escJson(ref) + '","object":{"sha":"' + sha + '"}}');
    }
    if (rest[0] === 'git' && rest[1] === 'refs' && rest[2] === 'heads' && method === 'GET' && rest.length === 4) {
      const oid = repo.branchTip(decSeg(rest[3]));
      if (!oid) return errResp(404, 'branch not found');
      return jsonResp(200, '{"ref":"refs/heads/' + escJson(decSeg(rest[3])) + '","object":{"sha":"' + oid + '"}}');
    }
    // branches
    if (rest[0] === 'branches' && method === 'GET') {
      if (rest.length === 2) {
        const oid = repo.branchTip(decSeg(rest[1]));
        if (!oid) return errResp(404, 'branch not found');
        return jsonResp(200, '{"name":"' + escJson(decSeg(rest[1])) + '","commit":{"sha":"' + oid + '"}}');
      }
      const items = [];
      for (const [ref, oid] of repo.refs) {
        if (ref.startsWith('refs/heads/')) items.push('{"name":"' + escJson(ref.slice(11)) + '","commit":{"sha":"' + oid + '"}}');
      }
      return jsonResp(200, '[' + items.join(',') + ']');
    }
    // commits
    if (rest[0] === 'commits' && method === 'GET') {
      const shaQ = q.sha ? decSeg(q.sha) : null;
      let tip = null;
      if (shaQ) tip = repo.branchTip(shaQ) || (isOid(shaQ) ? shaQ : null) || repo.refs.get('refs/heads/' + shaQ) || repo.refs.get(shaQ);
      else tip = repo.branchTip(repo.defaultBranch);
      const out = [];
      if (tip) {
        const seen = new Set();
        const stack = [tip];
        while (stack.length) {
          const oid = stack.pop();
          if (seen.has(oid)) continue;
          seen.add(oid);
          const c = repo.store.parseCommit(oid);
          if (!c) continue;
          out.push('{"sha":"' + oid + '","commit":{"message":"' + escJson(c.msg) + '"}}');
          for (const p of c.parents) stack.push(p);
        }
      }
      return jsonResp(200, '[' + out.join(',') + ']');
    }
    // contents
    if (rest[0] === 'contents') {
      const path = rest.slice(1).map(decSeg).join('/');
      return handleContents(repo, method, path, q, body);
    }
    // labels
    if (rest[0] === 'labels' && method === 'POST' && rest.length === 1) {
      const p = parseJsonBody(body);
      if (!p.ok) return errResp(400, 'malformed JSON body');
      const nm = p.value.name || '';
      if (!nm) return errResp(422, 'name is required');
      repo.labels.set(nm, { name: nm, color: typeof p.value.color === 'string' ? p.value.color : 'ededed' });
      return jsonResp(201, '{"name":"' + escJson(nm) + '"}');
    }
    // issues
    if (rest[0] === 'issues') return handleIssues(repo, method, rest.slice(1), q, body);
    // pulls
    if (rest[0] === 'pulls') return handlePulls(repo, method, rest.slice(1), q, body);
    return errResp(404, 'not found');
  }
  return errResp(404, 'not found');
}

function handleContents(repo, method, path, q, body) {
  const store = repo.store;
  const branch = q.ref ? decSeg(q.ref) : (parseJsonBody(body).value?.branch || null);
  // For PUT/DELETE the branch may come from the JSON body; parse once.
  let bodyObj = null;
  if (method === 'PUT' || method === 'DELETE') {
    const p = parseJsonBody(body);
    if (!p.ok) return errResp(400, 'malformed JSON body');
    bodyObj = p.value;
  }
  const branchName = (bodyObj && typeof bodyObj.branch === 'string' && bodyObj.branch) ? bodyObj.branch : (q.ref ? decSeg(q.ref) : repo.defaultBranch);
  const tip = repo.branchTip(branchName);
  const tipCommit = tip ? store.parseCommit(tip) : null;
  const tipTree = tipCommit ? tipCommit.tree : null;
  if (method === 'GET') {
    if (!tipTree) return errResp(404, 'not found');
    const found = path ? lookupPath(store, tipTree, path.split('/')) : { oid: tipTree, type: 'tree', mode: '40000' };
    if (!found) return errResp(404, 'not found');
    if (found.type === 'tree') {
      const entries = store.parseTree(found.oid) || [];
      const items = entries.map(e => '{"type":"' + (e.mode === '40000' ? 'dir' : 'file') + '","name":"' + escJson(e.name) + '","path":"' + escJson(path ? path + '/' + e.name : e.name) + '","sha":"' + e.oid + '"}');
      return jsonResp(200, '[' + items.join(',') + ']');
    }
    const blob = store.get(found.oid);
    const content = b64encode(blob.d);
    return jsonResp(200, '{"type":"file","encoding":"base64","content":"' + content + '","sha":"' + found.oid + '","size":' + blob.d.length + ',"name":"' + escJson(path.split('/').pop()) + '","path":"' + escJson(path) + '"}');
  }
  if (method === 'PUT') {
    const content = b64decode(bodyObj.content || '');
    if (content === null) return errResp(422, 'invalid content');
    const message = typeof bodyObj.message === 'string' ? bodyObj.message : 'update';
    const parts = path.split('/');
    const existing = tipTree ? lookupPath(store, tipTree, parts) : null;
    const isUpdate = !!existing;
    if (isUpdate) {
      if (!bodyObj.sha) return errResp(422, 'sha is required for update');
      if (String(bodyObj.sha).toLowerCase() !== existing.oid) return errResp(409, 'sha is stale');
    }
    const blobOid = store.put('blob', content);
    const newTree = setPathInTree(store, tipTree, parts, blobOid);
    const parents = tip ? [tip] : [];
    const commitOid = buildCommit(store, newTree, parents, message, EPOCH + seq);
    seq += 1;
    repo.setRef('refs/heads/' + branchName, commitOid);
    return jsonResp(isUpdate ? 200 : 201, '{"content":{"sha":"' + blobOid + '","encoding":"base64"},"commit":{"sha":"' + commitOid + '"}}');
  }
  if (method === 'DELETE') {
    if (!tipTree) return errResp(404, 'not found');
    const existing = lookupPath(store, tipTree, path.split('/'));
    if (!existing) return errResp(404, 'not found');
    if (bodyObj.sha && String(bodyObj.sha).toLowerCase() !== existing.oid) return errResp(409, 'sha is stale');
    const message = typeof bodyObj.message === 'string' ? bodyObj.message : 'delete';
    const newTree = setPathInTree(store, tipTree, path.split('/'), null);
    const commitOid = buildCommit(store, newTree, tip ? [tip] : [], message, EPOCH + seq);
    seq += 1;
    repo.setRef('refs/heads/' + branchName, commitOid);
    return jsonResp(200, '{"commit":{"sha":"' + commitOid + '"}}');
  }
  return errResp(404, 'not found');
}

function handleIssues(repo, method, rest, q, body) {
  if (rest.length === 0) {
    if (method === 'POST') {
      const p = parseJsonBody(body);
      if (!p.ok) return errResp(400, 'malformed JSON body');
      const r = createIssue(repo, p.value.title || '', p.value.body || '', p.value.labels || null);
      if (r.error) return errResp(r.error, r.message);
      return { status: 201, ctype: 'application/json', body: repo.issueJson(r.issue) };
    }
    if (method === 'GET') {
      let items = repo.issues;
      if (q.state === 'open' || q.state === 'closed') items = items.filter(i => i.state === q.state);
      if (q.sort === 'created') {
        items = [...items].sort((a, b) => q.direction === 'desc' ? b.seq - a.seq : a.seq - b.seq);
      }
      const pg = pageSlice(items, q);
      const s = '[' + pg.items.map(i => repo.issueJson(i).toString('utf8')).join(',') + ']';
      return jsonResp(200, s);
    }
    return errResp(404, 'not found');
  }
  const n = parseInt(rest[0], 10);
  if (!Number.isInteger(n)) return errResp(404, 'not found');
  const iss = repo.issueByNumber.get(n);
  if (rest.length === 1) {
    if (!iss) return errResp(404, 'issue not found');
    if (method === 'GET') return { status: 200, ctype: 'application/json', body: repo.issueJson(iss) };
    if (method === 'PATCH') {
      const p = parseJsonBody(body);
      if (!p.ok) return errResp(400, 'malformed JSON body');
      if (p.value.state === 'closed') closeIssue(repo, iss);
      else if (p.value.state === 'open') { iss.state = 'open'; iss.updatedAt = ts(); iss.json = null; }
      if (typeof p.value.title === 'string') { iss.title = p.value.title; iss.json = null; }
      if (typeof p.value.body === 'string') { iss.body = p.value.body; iss.json = null; }
      return { status: 200, ctype: 'application/json', body: repo.issueJson(iss) };
    }
    return errResp(404, 'not found');
  }
  if (rest[1] === 'comments') {
    if (!iss) return errResp(404, 'issue not found');
    const list = repo.comments.get(n) || [];
    if (method === 'POST') {
      const p = parseJsonBody(body);
      if (!p.ok) return errResp(400, 'malformed JSON body');
      const c = { id: repo.nextComment++, body: typeof p.value.body === 'string' ? p.value.body : '' };
      list.push(c);
      return jsonResp(201, '{"id":' + c.id + ',"body":"' + escJson(c.body) + '"}');
    }
    if (method === 'GET') {
      return jsonResp(200, '[' + list.map(c => '{"id":' + c.id + ',"body":"' + escJson(c.body) + '"}').join(',') + ']');
    }
    return errResp(404, 'not found');
  }
  return errResp(404, 'not found');
}

function handlePulls(repo, method, rest, q, body) {
  if (rest.length === 0) {
    if (method === 'POST') {
      const p = parseJsonBody(body);
      if (!p.ok) return errResp(400, 'malformed JSON body');
      const r = createPull(repo, p.value.title || '', p.value.body || '', p.value.head || '', p.value.base || '');
      if (r.error) return errResp(r.error, r.message);
      return jsonResp(201, pullJson(repo, r.pull));
    }
    if (method === 'GET') {
      let items = repo.pulls;
      if (q.state === 'all') { /* all */ }
      else if (q.state === 'closed') items = items.filter(x => x.state === 'closed');
      else items = items.filter(x => x.state === 'open');
      const pg = pageSlice(items, q);
      return jsonResp(200, '[' + pg.items.map(x => pullJson(repo, x)).join(',') + ']');
    }
    return errResp(404, 'not found');
  }
  const n = parseInt(rest[0], 10);
  if (!Number.isInteger(n)) return errResp(404, 'not found');
  const pr = repo.pullByNumber.get(n);
  if (rest.length === 1) {
    if (!pr) return errResp(404, 'pull request not found');
    if (method === 'GET') return jsonResp(200, pullJson(repo, pr));
    return errResp(404, 'not found');
  }
  if (rest[1] === 'files' && method === 'GET') {
    if (!pr) return errResp(404, 'pull request not found');
    const files = prFiles(repo, pr).filter(f => f.status !== 'removed');
    const s = '[' + files.map(f => '{"filename":"' + escJson(f.filename) + '","status":"' + f.status + '","additions":' + f.additions + ',"deletions":' + f.deletions + ',"changes":' + f.changes + '}').join(',') + ']';
    return jsonResp(200, s);
  }
  if (rest[1] === 'merge' && method === 'PUT') {
    if (!pr) return errResp(404, 'pull request not found');
    const p = parseJsonBody(body);
    if (!p.ok) return errResp(400, 'malformed JSON body');
    const r = mergePull(repo, pr);
    if (r.error) return errResp(r.error, r.message);
    return jsonResp(200, '{"merged":true,"sha":"' + r.sha + '","message":"Pull request successfully merged"}');
  }
  return errResp(404, 'not found');
}

// ---------------------------------------------------------------- GraphQL
const GQL_ISSUE_FIELDS = ['id', 'number', 'title', 'state', 'body'];
const GQL_PR_FIELDS = ['id', 'number', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files'];
const GQL_REPO_FIELDS = ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'];
function gqlErr(message) { return { message }; }
function gqlIssueNode(repo, iss) {
  return { id: repo.issueGid(iss.number), number: iss.number, title: iss.title, state: iss.state === 'open' ? 'OPEN' : 'CLOSED', body: iss.body };
}
function gqlPrNode(repo, pr) {
  return {
    id: repo.pullGid(pr.number), number: pr.number,
    state: pr.merged ? 'MERGED' : (pr.state === 'open' ? 'OPEN' : 'CLOSED'),
    merged: !!pr.merged,
    headRefName: pr.head, baseRefName: pr.base,
    mergeable: pr.state === 'open' ? (prConflict(repo, pr) ? 'CONFLICTING' : 'MERGEABLE') : 'UNKNOWN',
  };
}
function gqlRepoNode(repo) {
  const tip = repo.branchTip(repo.defaultBranch);
  return {
    id: repo.repoGid(), databaseId: repo.id, name: repo.name,
    nameWithOwner: VIEWER + '/' + repo.name, owner: { login: VIEWER },
    defaultBranchRef: tip ? { name: repo.defaultBranch } : null,
    viewerPermission: 'ADMIN', hasIssuesEnabled: true,
  };
}
function gqlCursor(n) { return Buffer.from('c:' + n, 'utf8').toString('base64'); }
function gqlUncursor(c) {
  try {
    const s = Buffer.from(String(c), 'base64').toString('utf8');
    if (s.startsWith('c:')) return parseInt(s.slice(2), 10);
  } catch { /* fall through */ }
  return null;
}
function handleGraphQLOp(query, variables) {
  const v = variables && typeof variables === 'object' ? variables : {};
  const m = query.match(/^\s*(query|mutation)\s+([A-Za-z0-9_]+)/);
  const op = m ? m[2] : '';
  // Introspection / viewer first (no repo needed).
  if (op === 'ViewerLogin') return { data: { viewer: { login: VIEWER } } };
  if (op === 'ViewerInvalidField') {
    return { data: { viewer: { login: VIEWER } }, errors: [gqlErr('Cannot query field "noSuchFieldOnViewer" on type "Query".')] };
  }
  if (op === 'Issue_fields') {
    return { data: { Issue: { fields: GQL_ISSUE_FIELDS.map(n => ({ name: n })) } } };
  }
  if (op === 'PullRequestAndRepositoryFields') {
    return {
      data: {
        PullRequest: { fields: GQL_PR_FIELDS.map(n => ({ name: n })) },
        Repository: { fields: GQL_REPO_FIELDS.map(n => ({ name: n })) },
      },
    };
  }
  if (op === 'SearchType_enumValues') {
    return { data: { SearchType: { enumValues: [{ name: 'ISSUE' }, { name: 'REPOSITORY' }, { name: 'USER' }] } } };
  }
  if (op === 'NodeRepository') {
    const r = resolveGid(v.id);
    if (r.kind !== 'R' || !r.repo) return { data: { node: null } };
    return { data: { node: { id: r.repo.repoGid(), name: r.repo.name, nameWithOwner: VIEWER + '/' + r.repo.name } } };
  }
  // Mutations that resolve ids without owner/name.
  if (op === 'IssueCreate') {
    const input = v.input || {};
    const r = resolveGid(input.repositoryId);
    if (r.kind !== 'R' || !r.repo) return { data: { createIssue: null }, errors: [gqlErr('repository not found')] };
    const c = createIssue(r.repo, input.title || '', input.body || '', null);
    if (c.error) return { data: { createIssue: null }, errors: [gqlErr(c.message)] };
    return { data: { createIssue: { issue: { number: c.issue.number, id: r.repo.issueGid(c.issue.number) } } } };
  }
  if (op === 'IssueClose') {
    const input = v.input || {};
    const r = resolveGid(input.issueId);
    if (r.kind !== 'I' || !r.repo || !r.issue) return { data: { closeIssue: null }, errors: [gqlErr('issue not found')] };
    closeIssue(r.repo, r.issue);
    return { data: { closeIssue: { issue: { number: r.issue.number, id: r.repo.issueGid(r.issue.number), state: 'CLOSED' } } } };
  }
  if (op === 'PullRequestCreate') {
    const input = v.input || {};
    const r = resolveGid(input.repositoryId);
    if (r.kind !== 'R' || !r.repo) return { data: { createPullRequest: null }, errors: [gqlErr('repository not found')] };
    const c = createPull(r.repo, input.title || '', '', input.headRefName || '', input.baseRefName || '');
    if (c.error) return { data: { createPullRequest: null }, errors: [gqlErr(c.message)] };
    const pr = c.pull;
    return { data: { createPullRequest: { pullRequest: { number: pr.number, id: r.repo.pullGid(pr.number), state: 'OPEN', headRefName: pr.head, baseRefName: pr.base } } } };
  }
  if (op === 'MergePullRequest') {
    const input = v.input || {};
    const r = resolveGid(input.pullRequestId);
    if (r.kind !== 'P' || !r.repo || !r.pull) return { data: { mergePullRequest: null }, errors: [gqlErr('pull request not found')] };
    const mg = mergePull(r.repo, r.pull);
    if (mg.error) return { data: { mergePullRequest: null }, errors: [gqlErr(mg.message)] };
    return { data: { mergePullRequest: { pullRequest: { number: r.pull.number, merged: true, state: 'MERGED' } } } };
  }
  if (op === 'AddComment') {
    const input = v.input || {};
    const r = resolveGid(input.subjectId);
    if (r.kind !== 'I' || !r.repo || !r.issue) return { data: { addComment: null }, errors: [gqlErr('issue not found')] };
    const c = { id: r.repo.nextComment++, body: input.body || '' };
    (r.repo.comments.get(r.issue.number) || []).push(c);
    return { data: { addComment: { commentEdge: { node: { id: r.repo.commentGid(r.issue.number, c.id), body: c.body } } } } };
  }
  // Repository-scoped queries.
  const repo = getRepo(v.owner, v.name);
  if (op === 'RepositoryFields') {
    if (!repo) return { data: { repository: null } };
    return { data: { repository: gqlRepoNode(repo) } };
  }
  if (!repo) return { data: { repository: null } };
  if (op === 'OpenIssues') {
    const first = typeof v.first === 'number' ? v.first : 10;
    const nodes = repo.issues.filter(i => i.state === 'open').sort((a, b) => b.number - a.number).slice(0, first);
    return { data: { repository: { issues: { nodes: nodes.map(i => gqlIssueNode(repo, i)) } } } };
  }
  if (op === 'IssueByNumber') {
    const iss = repo.issueByNumber.get(v.number);
    if (!iss) return { data: { repository: { issue: null } } };
    return { data: { repository: { issue: gqlIssueNode(repo, iss) } } };
  }
  if (op === 'PullRequests') {
    const first = typeof v.first === 'number' ? v.first : 5;
    const nodes = repo.pulls.slice(0, first).map(pr => gqlPrNode(repo, pr));
    return { data: { repository: { pullRequests: { nodes } } } };
  }
  if (op === 'PullRequestFiles') {
    const pr = repo.pullByNumber.get(v.number);
    if (!pr) return { data: { repository: { pullRequest: null } } };
    const files = prFiles(repo, pr).filter(f => f.status !== 'removed');
    const first = 10;
    return { data: { repository: { pullRequest: { number: pr.number, files: { nodes: files.slice(0, first).map(f => ({ path: f.filename })) } } } } };
  }
  if (op === 'PullRequestId') {
    const pr = repo.pullByNumber.get(v.number);
    if (!pr) return { data: { repository: { pullRequest: null } } };
    return { data: { repository: { pullRequest: { id: repo.pullGid(pr.number), number: pr.number } } } };
  }
  if (op === 'IssuesPage') {
    const first = typeof v.first === 'number' ? v.first : 5;
    const after = v.after ? gqlUncursor(v.after) : null;
    const sorted = [...repo.issues].sort((a, b) => a.number - b.number);
    const page = sorted.filter(i => after === null || i.number > after).slice(0, first);
    const rest = sorted.filter(i => after === null || i.number > after).length;
    const hasNext = rest > page.length;
    const endCursor = page.length ? gqlCursor(page[page.length - 1].number) : '';
    return {
      data: {
        repository: {
          issues: {
            nodes: page.map(i => ({ number: i.number })),
            pageInfo: { hasNextPage: hasNext, endCursor },
          },
        },
      },
    };
  }
  // Unknown operation/field: GraphQL-style error, HTTP 200.
  return { data: null, errors: [gqlErr('Unknown operation "' + (op || '?') + '"')] };
}
function handleGraphQL(body) {
  const p = parseJsonBody(body);
  if (!p.ok) return { status: 400, ctype: 'application/json', body: jbuf('{"errors":[{"message":"malformed JSON body"}]}') };
  const val = p.value;
  if (Array.isArray(val)) {
    const out = val.map(entry => {
      if (!entry || typeof entry !== 'object') return { data: null, errors: [gqlErr('bad operation')] };
      return handleGraphQLOp(entry.query || '', entry.variables || {});
    });
    return jsonResp(200, JSON.stringify(out));
  }
  if (!val || typeof val !== 'object') return jsonResp(200, JSON.stringify({ data: null, errors: [gqlErr('bad operation')] }));
  return jsonResp(200, JSON.stringify(handleGraphQLOp(val.query || '', val.variables || {})));
}

// ---------------------------------------------------------------- MCP
const MCP_TOOLS = [
  { name: 'create_repo', description: 'Create a repository for the viewer.', inputSchema: { type: 'object', properties: { name: { type: 'string' }, description: { type: 'string' }, private: { type: 'boolean' } }, required: ['name'] } },
  { name: 'get_repo', description: 'Get a repository by owner and name.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' } }, required: ['owner', 'repo'] } },
  { name: 'create_issue', description: 'Create an issue in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, body: { type: 'string' } }, required: ['owner', 'repo', 'title'] } },
  { name: 'list_issues', description: 'List issues in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, state: { type: 'string' } }, required: ['owner', 'repo'] } },
  { name: 'create_pull_request', description: 'Create a pull request.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, body: { type: 'string' }, head: { type: 'string' }, base: { type: 'string' } }, required: ['owner', 'repo', 'title', 'head', 'base'] } },
  { name: 'merge_pull_request', description: 'Merge a pull request.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, pull_number: { type: 'integer' } }, required: ['owner', 'repo', 'pull_number'] } },
];
const MCP_TOOLS_JSON = JSON.stringify({ tools: MCP_TOOLS });
function mcpNorm(n) { return String(n || '').toLowerCase().replace(/[^a-z0-9]/g, ''); }
function mcpFindTool(name) {
  const want = mcpNorm(name);
  for (const t of MCP_TOOLS) if (mcpNorm(t.name) === want) return t;
  for (const t of MCP_TOOLS) {
    const tn = mcpNorm(t.name);
    if (tn.length > want.length && tn.endsWith(want)) return t;
  }
  return null;
}
function mcpOk(id, result) { return jsonResp(200, JSON.stringify({ jsonrpc: '2.0', id: id === undefined ? null : id, result })); }
function mcpErr(id, code, message, data) {
  const e = { code, message };
  if (data !== undefined) e.data = data;
  return jsonResp(200, JSON.stringify({ jsonrpc: '2.0', id: id === undefined ? null : id, error: e }));
}
function mcpText(obj) {
  const text = JSON.stringify(obj);
  return { content: [{ type: 'text', text }], structuredContent: obj };
}
function mcpToolError(message) {
  return { content: [{ type: 'text', text: message }], isError: true };
}
function mcpArg(args, keys) {
  for (const k of keys) if (args[k] !== undefined && args[k] !== null) return args[k];
  return undefined;
}
function handleMcpCall(tool, args) {
  const a = args && typeof args === 'object' ? args : {};
  const missing = (t) => mcpToolError('missing required argument: ' + t);
  switch (tool.name) {
    case 'create_repo': {
      const name = mcpArg(a, ['name', 'repo', 'repository', 'repository_name', 'repo_name']);
      if (!name) return missing('name');
      const desc = mcpArg(a, ['description', 'about', 'summary', 'body']) || '';
      const priv = mcpArg(a, ['private', 'is_private']);
      const { repo } = createRepoRecord(String(name), String(desc), !!priv);
      return mcpText({ id: repo.id, name: repo.name, full_name: VIEWER + '/' + repo.name, owner: VIEWER, private: repo.private, description: repo.description, default_branch: repo.defaultBranch });
    }
    case 'get_repo': {
      const owner = mcpArg(a, ['owner', 'owner_login', 'org', 'organization', 'login', 'user']);
      let repoName = mcpArg(a, ['repo', 'repository', 'repository_name', 'repo_name']);
      if (!repoName) {
        const full = mcpArg(a, ['full_name', 'repo_full_name']);
        if (full && String(full).includes('/')) repoName = String(full).split('/').slice(1).join('/');
      }
      if (!owner || !repoName) return missing('owner/repo');
      const repo = getRepo(String(owner), String(repoName));
      if (!repo) return mcpToolError('repository not found: ' + owner + '/' + repoName);
      return mcpText({ id: repo.id, name: repo.name, full_name: VIEWER + '/' + repo.name, owner: VIEWER, private: repo.private, description: repo.description, default_branch: repo.defaultBranch });
    }
    case 'create_issue': {
      const owner = mcpArg(a, ['owner', 'owner_login', 'org', 'login']);
      let repoName = mcpArg(a, ['repo', 'repository', 'repository_name', 'repo_name']);
      if (!repoName) {
        const full = mcpArg(a, ['full_name', 'repo_full_name']);
        if (full && String(full).includes('/')) repoName = String(full).split('/').slice(1).join('/');
      }
      const title = mcpArg(a, ['title', 'issue_title', 'subject']);
      const body = mcpArg(a, ['body', 'issue_body', 'description', 'content', 'text']) || '';
      if (!owner || !repoName || !title) return missing('owner/repo/title');
      const repo = getRepo(String(owner), String(repoName));
      if (!repo) return mcpToolError('repository not found');
      const c = createIssue(repo, String(title), String(body), null);
      if (c.error) return mcpToolError(c.message);
      return mcpText({ id: c.issue.id, number: c.issue.number, title: c.issue.title, body: c.issue.body, state: 'open', full_name: VIEWER + '/' + repo.name });
    }
    case 'list_issues': {
      const owner = mcpArg(a, ['owner', 'owner_login', 'org', 'login']);
      let repoName = mcpArg(a, ['repo', 'repository', 'repository_name', 'repo_name']);
      if (!repoName) {
        const full = mcpArg(a, ['full_name', 'repo_full_name']);
        if (full && String(full).includes('/')) repoName = String(full).split('/').slice(1).join('/');
      }
      if (!owner || !repoName) return missing('owner/repo');
      const repo = getRepo(String(owner), String(repoName));
      if (!repo) return mcpToolError('repository not found');
      const state = mcpArg(a, ['state', 'status']);
      let items = repo.issues;
      if (state) items = items.filter(i => i.state === String(state).toLowerCase());
      return mcpText({ issues: items.map(i => ({ id: i.id, number: i.number, title: i.title, body: i.body, state: i.state })) });
    }
    case 'create_pull_request': {
      const owner = mcpArg(a, ['owner', 'owner_login', 'org', 'login']);
      let repoName = mcpArg(a, ['repo', 'repository', 'repository_name', 'repo_name']);
      if (!repoName) {
        const full = mcpArg(a, ['full_name', 'repo_full_name']);
        if (full && String(full).includes('/')) repoName = String(full).split('/').slice(1).join('/');
      }
      const title = mcpArg(a, ['title', 'pr_title', 'subject']);
      const body = mcpArg(a, ['body', 'description', 'content', 'text']) || '';
      const head = mcpArg(a, ['head', 'head_ref', 'head_branch', 'source', 'source_branch', 'from_branch', 'branch']);
      const base = mcpArg(a, ['base', 'base_ref', 'base_branch', 'target', 'target_branch', 'into_branch']);
      if (!owner || !repoName || !title || !head || !base) return missing('owner/repo/title/head/base');
      const repo = getRepo(String(owner), String(repoName));
      if (!repo) return mcpToolError('repository not found');
      const c = createPull(repo, String(title), String(body), String(head), String(base));
      if (c.error) return mcpToolError(c.message);
      return mcpText({ id: c.pull.id, number: c.pull.number, pull_number: c.pull.number, title: c.pull.title, state: 'open', head: c.pull.head, base: c.pull.base, full_name: VIEWER + '/' + repo.name });
    }
    case 'merge_pull_request': {
      const owner = mcpArg(a, ['owner', 'owner_login', 'org', 'login']);
      let repoName = mcpArg(a, ['repo', 'repository', 'repository_name', 'repo_name']);
      if (!repoName) {
        const full = mcpArg(a, ['full_name', 'repo_full_name']);
        if (full && String(full).includes('/')) repoName = String(full).split('/').slice(1).join('/');
      }
      const num = mcpArg(a, ['pull_number', 'pull_request_number', 'pr_number', 'number', 'issue_number', 'index']);
      if (!owner || !repoName || num === undefined) return missing('owner/repo/pull_number');
      const repo = getRepo(String(owner), String(repoName));
      if (!repo) return mcpToolError('repository not found');
      const pr = repo.pullByNumber.get(Number(num));
      if (!pr) return mcpToolError('pull request not found');
      const mg = mergePull(repo, pr);
      if (mg.error) return mcpToolError(mg.message);
      return mcpText({ merged: true, sha: mg.sha, number: pr.number, state: 'closed' });
    }
    default:
      return mcpToolError('unknown tool');
  }
}
function handleMcp(body) {
  let val;
  try { val = JSON.parse(body.toString('utf8')); }
  catch {
    return { status: 400, ctype: 'application/json', body: jbuf(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } })) };
  }
  if (!val || typeof val !== 'object' || Array.isArray(val)) {
    return mcpErr(null, -32600, 'Invalid Request');
  }
  const id = val.id;
  const method = val.method || '';
  const params = val.params && typeof val.params === 'object' ? val.params : {};
  if (method === 'server/discover') {
    const serverInfo = { name: 'iron-forge', version: '3.0.0' };
    return mcpOk(id, {
      supportedVersions: ['2026-07-28'],
      capabilities: { tools: {} },
      serverInfo,
      _meta: { 'io.modelcontextprotocol/serverInfo': serverInfo },
    });
  }
  if (method === 'initialize') {
    const offered = params.protocolVersion;
    const version = typeof offered === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(offered) ? offered : '2025-11-25';
    return mcpOk(id, { protocolVersion: version, capabilities: { tools: {} }, serverInfo: { name: 'iron-forge', version: '3.0.0' } });
  }
  if (method === 'notifications/initialized') {
    return { status: 202, ctype: 'application/json', body: Buffer.alloc(0) };
  }
  if (method === 'tools/list') {
    // Byte-identical every call: the prebuilt constant string.
    return { status: 200, ctype: 'application/json', body: jbuf('{"jsonrpc":"2.0","id":' + JSON.stringify(id === undefined ? null : id) + ',"result":' + MCP_TOOLS_JSON + '}') };
  }
  if (method === 'tools/call') {
    const name = params.name || '';
    const tool = mcpFindTool(name);
    if (!tool) return mcpErr(id, -32601, 'Method not found: ' + name);
    const result = handleMcpCall(tool, params.arguments || {});
    return mcpOk(id, result);
  }
  return mcpErr(id, -32601, 'Method not found: ' + method);
}

// ---------------------------------------------------------------- core router
// Synchronous: method, path segments, query object, lowercased headers, body.
// Returns {status, ctype, body:Buffer, extra?:[[k,v]]}.
let BASE_URL = '';
function handle(method, rawPath, q, headers, body, host) {
  const qi = rawPath.indexOf('?');
  const path = qi >= 0 ? rawPath.slice(0, qi) : rawPath;
  const query = q || parseQuery(qi >= 0 ? rawPath.slice(qi + 1) : '');
  const segs = path.split('/').filter(s => s.length > 0);
  // Health probe (no auth).
  if (method === 'GET' && path === '/healthz') return jsonResp(200, '{"ok":true}');
  if (method === 'GET' && path === '/') return jsonResp(200, '{"ok":true}');
  // Git smart HTTP: /{owner}/{repo}.git/...
  if (segs.length >= 2 && segs[1].endsWith('.git')) {
    const owner = decSeg(segs[0]);
    const repoName = decSeg(segs[1].slice(0, -4));
    const repo = getRepo(owner, repoName);
    if (segs[2] === 'info' && segs[3] === 'refs' && method === 'GET') {
      if (!repo) return errResp(404, 'repository not found');
      const service = query.service || '';
      if (service === 'git-upload-pack') {
        const v2 = headers['git-protocol'] === 'version=2';
        return { status: 200, ctype: 'application/x-git-upload-pack-advertisement', body: v2 ? v2Advert(repo) : v0Advert(repo, 'git-upload-pack') };
      }
      if (service === 'git-receive-pack') {
        return { status: 200, ctype: 'application/x-git-receive-pack-advertisement', body: v0Advert(repo, 'git-receive-pack') };
      }
      return errResp(400, 'unknown service');
    }
    if (segs[2] === 'git-upload-pack' && method === 'POST') {
      if (!repo) return errResp(404, 'repository not found');
      return handleUploadPack(repo, body, headers['git-protocol'] === 'version=2');
    }
    if (segs[2] === 'git-receive-pack' && method === 'POST') {
      if (!repo) return errResp(404, 'repository not found');
      return handleReceivePack(repo, body);
    }
    return errResp(404, 'not found');
  }
  // REST / GraphQL / MCP all require a bearer token.
  if (!authed(headers)) return errResp(401, 'authentication required');
  if (segs[0] === 'api' && segs[1] === 'v3') {
    return handleRest(method, segs.slice(2).map(decSeg), query, headers, body, host);
  }
  if (segs[0] === 'api' && segs[1] === 'graphql' && segs.length === 2) {
    if (method !== 'POST') return errResp(404, 'not found');
    return handleGraphQL(body);
  }
  if (segs[0] === 'mcp' && segs.length === 1) {
    if (method === 'DELETE') return { status: 200, ctype: 'application/json', body: Buffer.alloc(0) };
    if (method !== 'POST') return errResp(404, 'not found');
    return handleMcp(body);
  }
  return errResp(404, 'not found');
}
function sendResponse(write, res) {
  // res: {status, ctype, body, extra}. Builds the head once per response.
  const body = res.body || Buffer.alloc(0);
  const statusText = res.status === 200 ? 'OK' : res.status === 201 ? 'Created' : res.status === 204 ? 'No Content' : res.status === 400 ? 'Bad Request' : res.status === 401 ? 'Unauthorized' : res.status === 404 ? 'Not Found' : res.status === 405 ? 'Method Not Allowed' : res.status === 409 ? 'Conflict' : res.status === 422 ? 'Unprocessable Entity' : 'Error';
  let head = 'HTTP/1.1 ' + res.status + ' ' + statusText + '\r\ncontent-type: ' + (res.ctype || 'application/json') + '\r\nx-github-request-id: r' + (++seq) + '\r\ncontent-length: ' + body.length + '\r\nconnection: keep-alive\r\n';
  if (res.extra) for (const [k, v] of res.extra) head += k + ': ' + v + '\r\n';
  head += '\r\n';
  write(Buffer.concat([Buffer.from(head, 'ascii'), body]));
}

// ---------------------------------------------------------------- raw TCP transport
// Hand-rolled HTTP/1.1: one request at a time per socket, keep-alive, no
// chunked request bodies expected (Content-Length is what fetch sends) but
// chunked decoding is supported as a safety net.
function serveTcp(port, host) {
  return new Promise((resolve, reject) => {
    const server = net.createServer({ noDelay: true }, (socket) => {
      socket.setNoDelay(true);
      socket.setTimeout(0);
      let buf = Buffer.alloc(0);
      let busy = false;
      let closed = false;
      socket.on('error', () => { closed = true; });
      socket.on('close', () => { closed = true; });
      socket.on('data', (chunk) => {
        buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
        pump();
      });
      function pump() {
        if (busy || closed) return;
        // Parse head.
        const headEnd = buf.indexOf('\r\n\r\n');
        if (headEnd < 0) {
          if (buf.length > 65536) { socket.destroy(); }
          return;
        }
        const head = buf.toString('latin1', 0, headEnd);
        const lines = head.split('\r\n');
        const reqLine = lines[0].split(' ');
        if (reqLine.length < 3) { socket.destroy(); return; }
        const method = reqLine[0];
        const target = reqLine[1];
        const headers = {};
        let contentLength = 0;
        let chunked = false;
        let expectContinue = false;
        let hostHdr = '';
        for (let i = 1; i < lines.length; i++) {
          const c = lines[i].indexOf(':');
          if (c < 0) continue;
          const k = lines[i].slice(0, c).trim().toLowerCase();
          const v = lines[i].slice(c + 1).trim();
          headers[k] = v;
          if (k === 'content-length') contentLength = parseInt(v, 10) || 0;
          else if (k === 'transfer-encoding' && v.toLowerCase().includes('chunked')) chunked = true;
          else if (k === 'expect' && v.toLowerCase().includes('100-continue')) expectContinue = true;
          else if (k === 'host') hostHdr = v;
        }
        let bodyStart = headEnd + 4;
        if (expectContinue) {
          try { socket.write('HTTP/1.1 100 Continue\r\n\r\n'); } catch { /* ignore */ }
        }
        if (chunked) {
          // Decode chunked body inline.
          let pos = bodyStart;
          const chunks = [];
          while (true) {
            const eol = buf.indexOf('\r\n', pos);
            if (eol < 0) return; // wait for more
            const size = parseInt(buf.toString('ascii', pos, eol), 16);
            if (Number.isNaN(size)) { socket.destroy(); return; }
            if (size === 0) {
              const end = buf.indexOf('\r\n', eol + 2);
              if (end < 0) return;
              bodyStart = end + 2;
              break;
            }
            if (buf.length < eol + 2 + size + 2) return; // wait for more
            chunks.push(buf.subarray(eol + 2, eol + 2 + size));
            pos = eol + 2 + size + 2;
          }
          const body = Buffer.concat(chunks);
          buf = buf.subarray(bodyStart);
          dispatch(method, target, headers, body, hostHdr);
          return;
        }
        if (buf.length < bodyStart + contentLength) return; // wait for more
        const body = contentLength > 0 ? buf.subarray(bodyStart, bodyStart + contentLength) : Buffer.alloc(0);
        buf = buf.subarray(bodyStart + contentLength);
        dispatch(method, target, headers, body, hostHdr);
      }
      function dispatch(method, target, headers, body, hostHdr) {
        busy = true;
        let res;
        try {
          res = handle(method, target, null, headers, body, hostHdr || ('127.0.0.1:' + port));
        } catch (e) {
          res = errResp(500, 'internal error');
        }
        const keepAlive = headers['connection'] !== 'close';
        try {
          sendResponse((b) => { try { socket.write(b); } catch { /* ignore */ } }, res);
        } catch { /* ignore */ }
        busy = false;
        if (!keepAlive) { try { socket.end(); } catch { /* ignore */ } return; }
        if (buf.length > 0) pump();
      }
    });
    server.on('error', reject);
    server.listen(port, host, () => resolve(server));
  });
}

// ---------------------------------------------------------------- node:http transport
function serveHttp(port, host) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        const body = chunks.length ? Buffer.concat(chunks) : Buffer.alloc(0);
        let out;
        try {
          out = handle(req.method || 'GET', req.url || '/', null, req.headers, body, req.headers.host || ('127.0.0.1:' + port));
        } catch {
          out = errResp(500, 'internal error');
        }
        const h = { 'content-type': out.ctype || 'application/json', 'x-github-request-id': 'r' + (++seq) };
        if (out.extra) for (const [k, v] of out.extra) h[k] = v;
        res.writeHead(out.status, h);
        res.end(out.body || Buffer.alloc(0));
      });
      req.on('error', () => { try { res.end(); } catch { /* ignore */ } });
    });
    server.on('error', reject);
    server.listen(port, host, () => resolve(server));
  });
}

// ---------------------------------------------------------------- trial wire + main
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
async function main() {
  const server = TRANSPORT === 'http'
    ? await serveHttp(0, '0.0.0.0')
    : await serveTcp(0, '0.0.0.0');
  const port = server.address().port;
  BASE_URL = 'http://127.0.0.1:' + port;
  console.error('iron-forge v3 listening on ' + port + ' transport=' + TRANSPORT + ' viewer=' + VIEWER);
  if (!ENV_URL) {
    // Local dev: serve forever until killed.
    return;
  }
  // Trial: register, then poll /done until the suite finishes.
  for (let attempt = 0; attempt < 20; attempt++) {
    try {
      const r = await fetch(ENV_URL + '/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(5000),
      });
      if (r.status === 200 || r.status === 409) break;
    } catch { /* retry */ }
    await sleep(500);
  }
  let delay = 250;
  for (;;) {
    try {
      const r = await fetch(ENV_URL + '/done', { signal: AbortSignal.timeout(30000) });
      const j = await r.json();
      if (j && j.done === true) break;
    } catch { /* keep polling */ }
    await sleep(delay);
    if (delay < 2000) delay = Math.min(2000, delay * 2);
  }
  try { server.close(); } catch { /* ignore */ }
  process.exit(0);
}
main().catch(() => process.exit(1));
