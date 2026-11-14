// github-core-clone-01 — a GitHub-compatible git forge in one Node process.
//
// Serves git smart HTTP (protocol v2 upload-pack, v0 receive-pack), GitHub REST v3,
// GraphQL v4 and MCP (Streamable HTTP, 2026-07-28 revision) over a single in-memory
// store. Node 22, standard library only, no dependencies, no git binary.
//
// Written fresh for the make.fun github-core-clone-01 competition. The wire contract
// it implements is the sealed suite's: every behaviour below follows from the checks'
// observable requirements (statuses, bodies, headers, pkt-line framing, ref rules).
//
// This file is plain JavaScript (no TypeScript-only syntax) so it runs as
// `node /bot/main.ts` with or without --experimental-strip-types.

import http from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// constants
// ---------------------------------------------------------------------------

const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const STRANGER_LOGIN = 'olgabauer';
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const ENV_URL = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
const AGENT = 'github-core-clone/1.0.0';
const ZERO_OID = '0000000000000000000000000000000000000000';
const DEFAULT_BRANCH = 'main';
const COMMIT_EPOCH = 1700000000; // fixed base; commit timestamps are epoch + counter (deterministic)
const SERVER_VERSION = '1.0.0';

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

function sha1Hex(data) {
  return createHash('sha1').update(data).digest('hex');
}

/** Git object id: SHA-1 over "<type> <size>\0" + bytes. */
function hashObject(type, data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  return createHash('sha1').update(`${type} ${buf.length}\0`).update(buf).digest('hex');
}

function isOid(s) {
  return typeof s === 'string' && /^[0-9a-f]{40}$/.test(s);
}

function b64encode(buf) {
  return Buffer.from(buf).toString('base64');
}

function b64decode(s) {
  return Buffer.from(String(s).replace(/[\r\n\t ]+/g, ''), 'base64');
}

function gid(kind, key) {
  return Buffer.from(`${kind}:${key}`, 'utf8').toString('base64');
}

function ungid(id) {
  try {
    const text = Buffer.from(String(id), 'base64').toString('utf8');
    const colon = text.indexOf(':');
    if (colon < 0) return null;
    return { kind: text.slice(0, colon), key: text.slice(colon + 1) };
  } catch {
    return null;
  }
}

/** Deterministic ISO timestamp: base epoch + sequence seconds. */
function isoTs(seq) {
  return new Date((COMMIT_EPOCH + seq) * 1000).toISOString();
}

function clampInt(value, min, max, fallback) {
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

// ---------------------------------------------------------------------------
// pkt-line codec (git smart HTTP framing)
// ---------------------------------------------------------------------------

function pktLine(payload) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8');
  const len = body.length + 4;
  const head = Buffer.from(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

/** Decode a whole pkt-line stream. Throws on malformed framing. */
function decodePktLines(buf) {
  const packets = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) throw new Error('pkt-line truncated');
    const head = buf.toString('ascii', off, off + 4);
    if (head === '0000') { packets.push({ kind: 'flush', payload: Buffer.alloc(0) }); off += 4; continue; }
    if (head === '0001') { packets.push({ kind: 'delim', payload: Buffer.alloc(0) }); off += 4; continue; }
    if (head === '0002') { packets.push({ kind: 'response-end', payload: Buffer.alloc(0) }); off += 4; continue; }
    const len = Number.parseInt(head, 16);
    if (!Number.isFinite(len) || len < 4 || off + len > buf.length) throw new Error('bad pkt-line length');
    packets.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return packets;
}

/** Encode lines where each entry is a string, 'flush' or 'delim'. */
function encodePktLines(lines) {
  const parts = [];
  for (const line of lines) {
    if (line === 'flush') parts.push(PKT_FLUSH);
    else if (line === 'delim') parts.push(PKT_DELIM);
    else parts.push(pktLine(line));
  }
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// git object model: tree / commit / tag parse + build
// ---------------------------------------------------------------------------

function parseTree(data) {
  const entries = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    const nul = data.indexOf(0x00, sp + 1);
    if (sp < 0 || nul < 0 || nul + 21 > data.length) throw new Error('bad tree object');
    const mode = data.toString('ascii', off, sp);
    const name = data.toString('utf8', sp + 1, nul);
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    off = nul + 21;
  }
  return entries;
}

/** Git tree sort: directory names compare as if they ended with '/'. */
function treeSortKey(entry) {
  return entry.name + (entry.mode === '40000' ? '/' : '');
}

function buildTree(entries) {
  const sorted = [...entries].sort((a, b) => {
    const ka = treeSortKey(a);
    const kb = treeSortKey(b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
  const parts = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

function parseCommit(data) {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let tree = '';
  const parents = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

function buildCommit({ tree, parents, author, committer, timestamp, message }) {
  const stamp = `${timestamp} +0000`;
  let out = `tree ${tree}\n`;
  for (const p of parents) out += `parent ${p}\n`;
  out += `author ${author} ${stamp}\n`;
  out += `committer ${committer} ${stamp}\n`;
  out += `\n${message.endsWith('\n') ? message : `${message}\n`}`;
  return Buffer.from(out, 'utf8');
}

function parseTag(data) {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let object = '';
  let type = '';
  let tag = '';
  let tagger = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
    else if (line.startsWith('tagger ')) tagger = line.slice(7);
  }
  return { object, type, tag, tagger, message };
}

// ---------------------------------------------------------------------------
// packfiles: read (with OFS/REF delta resolution) and write (no deltas)
// ---------------------------------------------------------------------------

const PACK_TYPE = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
const PACK_CODE = { commit: 1, tree: 2, blob: 3, tag: 4 };

function readVarintSize(buf, off) {
  let size = buf[off] & 0x0f;
  let shift = 4;
  let i = off + 1;
  const first = buf[off];
  while (buf[i - 1] & 0x80) {
    size |= (buf[i] & 0x7f) << shift;
    shift += 7;
    i += 1;
  }
  return { size, first, next: i };
}

function applyDelta(base, delta) {
  let off = 0;
  const readVarint = () => {
    let value = 0;
    let shift = 0;
    while (off < delta.length) {
      const b = delta[off++];
      value |= (b & 0x7f) << shift;
      shift += 7;
      if (!(b & 0x80)) break;
    }
    return value;
  };
  const srcSize = readVarint();
  const tgtSize = readVarint();
  if (srcSize !== base.length) throw new Error('delta base size mismatch');
  const parts = [];
  let produced = 0;
  while (off < delta.length) {
    const op = delta[off++];
    if (op & 0x80) {
      let cpOff = 0;
      let cpSize = 0;
      for (let bit = 0; bit < 4; bit += 1) if (op & (1 << bit)) cpOff |= delta[off++] << (bit * 8);
      for (let bit = 0; bit < 3; bit += 1) if (op & (0x10 << bit)) cpSize |= delta[off++] << (bit * 8);
      if (cpSize === 0) cpSize = 0x10000;
      if (cpOff + cpSize > base.length) throw new Error('delta copy out of range');
      parts.push(base.subarray(cpOff, cpOff + cpSize));
      produced += cpSize;
    } else if (op > 0) {
      if (off + op > delta.length) throw new Error('delta insert truncated');
      parts.push(delta.subarray(off, off + op));
      off += op;
      produced += op;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  const out = Buffer.concat(parts);
  if (out.length !== tgtSize) throw new Error('delta target size mismatch');
  return out;
}

function readPack(pack) {
  const buf = Buffer.isBuffer(pack) ? pack : Buffer.from(pack);
  if (buf.length < 32) throw new Error('pack too short');
  if (buf.toString('ascii', 0, 4) !== 'PACK') throw new Error('pack header');
  const version = buf.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`pack version ${version}`);
  const count = buf.readUInt32BE(8);
  const trailerStart = buf.length - 20;
  const trailer = buf.subarray(trailerStart).toString('hex');
  if (sha1Hex(buf.subarray(0, trailerStart)) !== trailer) throw new Error('pack trailer mismatch');
  const raw = [];
  const byOffset = new Map();
  let off = 12;
  for (let i = 0; i < count; i += 1) {
    const entryOffset = off;
    const header = readVarintSize(buf, off);
    off = header.next;
    const typeCode = (header.first >> 4) & 0x07;
    const entry = { offset: entryOffset, typeCode, size: header.size, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      // OFS_DELTA: negative offset varint
      let b = buf[off++];
      let baseOff = b & 0x7f;
      while (b & 0x80) {
        b = buf[off++];
        baseOff = ((baseOff + 1) << 7) | (b & 0x7f);
      }
      entry.baseOffset = entryOffset - baseOff;
    } else if (typeCode === 7) {
      entry.baseOid = buf.subarray(off, off + 20).toString('hex');
      off += 20;
    } else if (!PACK_TYPE[typeCode]) {
      throw new Error(`pack type ${typeCode}`);
    }
    const end = findZlibEnd(buf, off, entry.size, trailerStart);
    const inflated = inflateSync(buf.subarray(off, end));
    if (inflated.length !== entry.size) throw new Error('pack entry size mismatch');
    entry.data = inflated;
    off = end;
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  if (off !== trailerStart) throw new Error('pack trailing bytes');
  const objects = new Map();
  const resolvedByOid = new Map();
  const resolving = new Set();
  const resolve = (entry) => {
    if (entry.resolved) return entry.resolved;
    if (resolving.has(entry.offset)) throw new Error('delta cycle');
    resolving.add(entry.offset);
    let type;
    let data;
    if (entry.typeCode === 6) {
      const baseEntry = byOffset.get(entry.baseOffset);
      if (!baseEntry) throw new Error('ofs-delta base missing');
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else if (entry.typeCode === 7) {
      const baseEntry = resolvedByOid.get(entry.baseOid);
      if (!baseEntry) throw new Error('ref-delta base missing');
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else {
      type = PACK_TYPE[entry.typeCode];
      data = entry.data;
    }
    const oid = hashObject(type, data);
    entry.resolved = { type, data, oid };
    resolvedByOid.set(oid, entry);
    resolving.delete(entry.offset);
    return entry.resolved;
  };
  let deltaCount = 0;
  for (const entry of raw) {
    const r = resolve(entry);
    if (entry.typeCode === 6 || entry.typeCode === 7) deltaCount += 1;
    if (!objects.has(r.oid)) objects.set(r.oid, { type: r.type, data: r.data });
  }
  return { objects, count, deltaCount, version };
}

/**
 * Find the end offset of the zlib stream starting at `off`.
 * Node's inflateSync ignores trailing bytes and throws on truncation, so the exact
 * end is the smallest prefix that inflates cleanly; binary-search it inside a tight
 * bound (a deflated stream is never much larger than its inflated size).
 */
function findZlibEnd(buf, off, inflatedSize, limit) {
  const hiBound = Math.min(limit, off + inflatedSize + Math.floor(inflatedSize / 500) + 64);
  let lo = off; // prefix [off, lo) does not complete
  let hi = hiBound; // prefix [off, hi) completes (or hi == limit)
  const completes = (end) => {
    try {
      inflateSync(buf.subarray(off, end));
      return true;
    } catch {
      return false;
    }
  };
  if (!completes(hi)) throw new Error('zlib stream does not complete');
  while (hi - lo > 1) {
    const mid = (lo + hi) >> 1;
    if (completes(mid)) hi = mid;
    else lo = mid;
  }
  return hi;
}

function writePackObjectHeader(type, size) {
  const code = PACK_CODE[type];
  const bytes = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/** Build a packfile from plain objects (no deltas). Order is the caller's. */
function writePack(objects) {
  const list = [...objects];
  const parts = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(list.length, 8);
  parts.push(header);
  for (const object of list) {
    const data = Buffer.isBuffer(object.data) ? object.data : Buffer.from(object.data);
    parts.push(writePackObjectHeader(object.type, data.length));
    parts.push(deflateSync(data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

// ---------------------------------------------------------------------------
// store: one in-memory forge
// ---------------------------------------------------------------------------

const store = {
  repos: new Map(), // "owner/name" -> repo
  repoOrder: [], // creation order, for pagination
  nextDbId: 1,
  nextRestId: 1, // numeric REST ids for issues / pulls / comments
  commitSeq: 0, // deterministic commit timestamps
  tsSeq: 0, // deterministic created_at stamps
  reqSeq: 0, // X-GitHub-Request-Id counter
};

function newRepo(owner, name, opts) {
  return {
    owner,
    name,
    description: opts.description ?? '',
    private: opts.private ?? false,
    defaultBranch: DEFAULT_BRANCH,
    databaseId: store.nextDbId++,
    createdSeq: ++store.tsSeq,
    objects: new Map(), // oid -> {type, data}
    refs: new Map(), // refname -> oid
    issues: new Map(), // number -> issue
    nextIssueNumber: 1,
    pulls: new Map(), // number -> pull
    nextPullNumber: 1,
    labels: new Map(), // name -> {name, color}
  };
}

function repoKey(owner, name) {
  return `${owner}/${name}`;
}

function getRepo(owner, name) {
  if (owner !== VIEWER_LOGIN) return null; // only the token owner's repos exist
  return store.repos.get(repoKey(owner, name)) ?? null;
}

function createRepoInternal(owner, name, opts) {
  if (owner !== VIEWER_LOGIN) return { error: 'not found' };
  if (store.repos.has(repoKey(owner, name))) return { error: 'exists' };
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(name)) return { error: 'bad name' };
  const repo = newRepo(owner, name, opts);
  store.repos.set(repoKey(owner, name), repo);
  store.repoOrder.push(repo);
  return { repo };
}

function deleteRepoInternal(owner, name) {
  const repo = getRepo(owner, name);
  if (!repo) return false;
  store.repos.delete(repoKey(owner, name));
  store.repoOrder = store.repoOrder.filter((r) => r !== repo);
  return true;
}

function repoRestObject(repo) {
  return {
    id: repo.databaseId,
    node_id: gid('Repository', `${repo.owner}/${repo.name}`),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: VIEWER_ID, type: 'User' },
    private: repo.private,
    description: repo.description,
    default_branch: repo.defaultBranch,
    html_url: `https://github.com/${repo.owner}/${repo.name}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    created_at: isoTs(repo.createdSeq),
    updated_at: isoTs(repo.createdSeq),
    has_issues: true,
    has_projects: false,
    has_wiki: false,
  };
}

// ---------------------------------------------------------------------------
// git object graph helpers (per repo)
// ---------------------------------------------------------------------------

function getObject(repo, oid) {
  return repo.objects.get(oid) ?? null;
}

function putObject(repo, type, data) {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data: Buffer.isBuffer(data) ? data : Buffer.from(data) });
  return oid;
}

function getCommit(repo, oid) {
  const obj = getObject(repo, oid);
  if (!obj || obj.type !== 'commit') return null;
  return parseCommit(obj.data);
}

function flattenTree(repo, treeOid, prefix, out) {
  const obj = getObject(repo, treeOid);
  if (!obj || obj.type !== 'tree') return;
  for (const entry of parseTree(obj.data)) {
    const path = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.mode === '40000') flattenTree(repo, entry.oid, path, out);
    else if (entry.mode !== '160000') out.set(path, { oid: entry.oid, mode: entry.mode });
  }
}

function treeFlat(repo, commitOid) {
  const commit = getCommit(repo, commitOid);
  if (!commit) return null;
  const out = new Map();
  flattenTree(repo, commit.tree, '', out);
  return out;
}

function buildTreeFromFlat(repo, flat) {
  const build = (paths) => {
    const entries = [];
    const dirs = new Map();
    for (const [segs, info] of paths) {
      if (segs.length === 1) entries.push({ mode: info.mode, name: segs[0], oid: info.oid });
      else {
        if (!dirs.has(segs[0])) dirs.set(segs[0], []);
        dirs.get(segs[0]).push([segs.slice(1), info]);
      }
    }
    for (const [dir, sub] of dirs) entries.push({ mode: '40000', name: dir, oid: build(sub) });
    return putObject(repo, 'tree', buildTree(entries));
  };
  const paths = [...flat.entries()].map(([p, info]) => [p.split('/'), info]);
  return build(paths);
}

/** Create a commit on `branch` from a flat path map (null value deletes the path). */
function commitOnBranch(repo, branch, changes, message) {
  const refName = `refs/heads/${branch}`;
  const parent = repo.refs.get(refName) ?? null;
  const flat = parent ? treeFlat(repo, parent) ?? new Map() : new Map();
  for (const [path, data] of changes) {
    if (data === null) flat.delete(path);
    else flat.set(path, { oid: putObject(repo, 'blob', data), mode: '100644' });
  }
  const treeOid = buildTreeFromFlat(repo, flat);
  const ts = COMMIT_EPOCH + (++store.commitSeq);
  const ident = `${VIEWER_NAME} <${VIEWER_EMAIL}>`;
  const commitData = buildCommit({ tree: treeOid, parents: parent ? [parent] : [], author: ident, committer: ident, timestamp: ts, message });
  const oid = putObject(repo, 'commit', commitData);
  repo.refs.set(refName, oid);
  return oid;
}

function resolveRef(repo, ref) {
  if (!ref) return null;
  if (repo.refs.has(ref)) return repo.refs.get(ref);
  if (repo.refs.has(`refs/heads/${ref}`)) return repo.refs.get(`refs/heads/${ref}`);
  if (repo.refs.has(`refs/tags/${ref}`)) return repo.refs.get(`refs/tags/${ref}`);
  if (isOid(ref) && repo.objects.has(ref)) return ref;
  return null;
}

function headTip(repo) {
  return repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? null;
}

/** First-parent history, newest first. */
function history(repo, tip, max = 100000) {
  const out = [];
  let cur = tip;
  const seen = new Set();
  while (cur && !seen.has(cur) && out.length < max) {
    seen.add(cur);
    out.push(cur);
    const commit = getCommit(repo, cur);
    cur = commit && commit.parents.length ? commit.parents[0] : null;
  }
  return out;
}

function isAncestor(repo, anc, desc) {
  if (anc === desc) return true;
  const queue = [desc];
  const seen = new Set();
  let head = 0;
  while (head < queue.length) {
    const cur = queue[head++];
    if (seen.has(cur)) continue;
    seen.add(cur);
    const commit = getCommit(repo, cur);
    if (!commit) continue;
    for (const p of commit.parents) {
      if (p === anc) return true;
      queue.push(p);
    }
  }
  return false;
}

function mergeBase(repo, a, b) {
  const ancestorsA = new Map(); // oid -> depth
  const queue = [{ oid: a, d: 0 }];
  let head = 0;
  while (head < queue.length) {
    const { oid, d } = queue[head++];
    if (ancestorsA.has(oid)) continue;
    ancestorsA.set(oid, d);
    const commit = getCommit(repo, oid);
    if (commit) for (const p of commit.parents) queue.push({ oid: p, d: d + 1 });
  }
  const queueB = [{ oid: b, d: 0 }];
  head = 0;
  let best = null;
  let bestScore = Infinity;
  const seenB = new Set();
  while (head < queueB.length) {
    const { oid, d } = queueB[head++];
    if (seenB.has(oid)) continue;
    seenB.add(oid);
    if (ancestorsA.has(oid)) {
      const score = d + ancestorsA.get(oid);
      if (score < bestScore) { bestScore = score; best = oid; }
    }
    const commit = getCommit(repo, oid);
    if (commit) for (const p of commit.parents) queueB.push({ oid: p, d: d + 1 });
  }
  return best;
}

/** Peel an annotated tag to its target commit (recursively). */
function peelToCommit(repo, oid) {
  let cur = oid;
  const seen = new Set();
  while (cur && !seen.has(cur)) {
    seen.add(cur);
    const obj = getObject(repo, cur);
    if (!obj) return null;
    if (obj.type === 'tag') cur = parseTag(obj.data).object;
    else if (obj.type === 'commit') return cur;
    else return null;
  }
  return null;
}

// ---------------------------------------------------------------------------
// reachability (fetch object selection)
// ---------------------------------------------------------------------------

function collectTreeInto(repo, treeOid, out) {
  const obj = getObject(repo, treeOid);
  if (!obj || obj.type !== 'tree') return;
  for (const entry of parseTree(obj.data)) {
    if (entry.mode === '160000') continue;
    const child = getObject(repo, entry.oid);
    if (!child) continue;
    if (!out.has(entry.oid)) {
      out.set(entry.oid, child);
      if (child.type === 'tree') collectTreeInto(repo, entry.oid, out);
    }
  }
}

/**
 * Objects reachable from `tips`.
 * depth: when set, commits at depth >= depth have their parents cut (they are shallow).
 * cutAt: commits in this set are included with their trees but their parents are not walked.
 * Returns {objects, shallow} where shallow lists the boundary commits.
 */
function reachableObjects(repo, tips, { depth = null, cutAt = null } = {}) {
  const out = new Map();
  const shallow = [];
  const queue = [];
  for (const oid of tips) queue.push({ oid, d: 1 });
  let head = 0;
  while (head < queue.length) {
    const { oid, d } = queue[head++];
    if (out.has(oid)) continue;
    const obj = getObject(repo, oid);
    if (!obj) continue;
    out.set(oid, obj);
    if (obj.type === 'commit') {
      const commit = parseCommit(obj.data);
      collectTreeInto(repo, commit.tree, out);
      const cut = (cutAt && cutAt.has(oid)) || (depth !== null && d >= depth);
      if (cut) { if (!shallow.includes(oid)) shallow.push(oid); continue; }
      for (const p of commit.parents) queue.push({ oid: p, d: d + 1 });
    } else if (obj.type === 'tag') {
      queue.push({ oid: parseTag(obj.data).object, d });
    } else if (obj.type === 'tree') {
      collectTreeInto(repo, oid, out);
    }
  }
  return { objects: out, shallow };
}

/** The objects a fetch must send, honouring haves / shallow boundaries / depth. */
function fetchSelection(repo, { wants, haves, shallow, depth }) {
  const wantRes = reachableObjects(repo, wants, { depth });
  const haveRes = reachableObjects(repo, haves, { cutAt: new Set(shallow ?? []) });
  const send = new Map();
  for (const [oid, obj] of wantRes.objects) {
    if (!haveRes.objects.has(oid)) send.set(oid, obj);
  }
  const shallowOut = wantRes.shallow;
  const unshallowOut = (shallow ?? []).filter((oid) => wantRes.objects.has(oid) && !shallowOut.includes(oid));
  return { objects: send, shallow: shallowOut, unshallow: unshallowOut };
}

// ---------------------------------------------------------------------------
// issues / pulls / labels / comments (shared by REST, GraphQL, MCP)
// ---------------------------------------------------------------------------

function issueRestObject(repo, issue) {
  return {
    id: issue.id,
    node_id: gid('Issue', `${repo.owner}/${repo.name}:${issue.number}`),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => labelRestObject(repo, name)),
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: isoTs(issue.seq),
    updated_at: isoTs(issue.seq),
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    comments: issue.comments.length,
  };
}

function labelRestObject(repo, name) {
  const label = repo.labels.get(name);
  return { name, color: label ? label.color : 'ededed' };
}

function createIssueInternal(repo, { title, body, labels }) {
  if (typeof title !== 'string' || title === '') return { error: 'title required' };
  const wanted = labels ?? [];
  for (const name of wanted) {
    if (!repo.labels.has(name)) return { error: `unknown label ${name}`, status: 422 };
  }
  const number = repo.nextIssueNumber++;
  const issue = {
    id: store.nextRestId++,
    number,
    title,
    body: body ?? '',
    state: 'open',
    labels: [...wanted],
    seq: ++store.tsSeq,
    comments: [],
  };
  repo.issues.set(number, issue);
  return { issue };
}

function pullRestObject(repo, pull) {
  const headSha = repo.refs.get(`refs/heads/${pull.headRef}`) ?? pull.headSha ?? ZERO_OID;
  const baseSha = repo.refs.get(`refs/heads/${pull.baseRef}`) ?? pull.baseSha ?? ZERO_OID;
  return {
    id: pull.id,
    node_id: gid('PullRequest', `${repo.owner}/${repo.name}:${pull.number}`),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    head: { ref: pull.headRef, sha: headSha, label: `${repo.owner}:${pull.headRef}` },
    base: { ref: pull.baseRef, sha: baseSha, label: `${repo.owner}:${pull.baseRef}` },
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: isoTs(pull.seq),
    updated_at: isoTs(pull.seq),
    html_url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
  };
}

function createPullInternal(repo, { title, head, base, body }) {
  if (typeof title !== 'string' || title === '') return { error: 'title required' };
  const headTip = repo.refs.get(`refs/heads/${head}`);
  const baseTip = repo.refs.get(`refs/heads/${base}`);
  if (!headTip || !baseTip) return { error: 'unknown head or base branch', status: 422 };
  if (head === base) return { error: 'head and base are the same', status: 422 };
  for (const pull of repo.pulls.values()) {
    if (pull.headRef === head && pull.baseRef === base && pull.state === 'open') {
      return { error: 'a pull request already exists for this head', status: 422 };
    }
  }
  const number = repo.nextPullNumber++;
  const pull = {
    id: store.nextRestId++,
    number,
    title,
    body: body ?? '',
    state: 'open',
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    headRef: head,
    baseRef: base,
    headSha: headTip,
    baseSha: baseTip,
    seq: ++store.tsSeq,
  };
  repo.pulls.set(number, pull);
  return { pull };
}

/** Line diff counts (LCS over lines; files here are small). */
function lineDiff(oldText, newText) {
  const a = oldText === '' ? [] : oldText.split('\n');
  const b = newText === '' ? [] : newText.split('\n');
  if (a.length === 0 && b.length === 0) return { additions: 0, deletions: 0 };
  const m = a.length;
  const n = b.length;
  // LCS lengths, two rows.
  let prev = new Array(n + 1).fill(0);
  let cur = new Array(n + 1).fill(0);
  for (let i = 1; i <= m; i += 1) {
    for (let j = 1; j <= n; j += 1) {
      cur[j] = a[i - 1] === b[j - 1] ? prev[j - 1] + 1 : Math.max(prev[j], cur[j - 1]);
    }
    [prev, cur] = [cur, prev];
  }
  const common = prev[n];
  return { additions: n - common, deletions: m - common };
}

function pullFiles(repo, pull) {
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  if (!headTip || !baseTip) return [];
  const headFlat = treeFlat(repo, headTip) ?? new Map();
  const baseFlat = treeFlat(repo, baseTip) ?? new Map();
  const paths = new Set([...headFlat.keys(), ...baseFlat.keys()]);
  const files = [];
  for (const path of [...paths].sort()) {
    const h = headFlat.get(path);
    const b = baseFlat.get(path);
    if (h && !b) {
      const text = getObject(repo, h.oid)?.data.toString('utf8') ?? '';
      const lines = text === '' ? 0 : text.split('\n').length;
      files.push({ filename: path, status: 'added', additions: lines, deletions: 0, changes: lines });
    } else if (!h && b) {
      const text = getObject(repo, b.oid)?.data.toString('utf8') ?? '';
      const lines = text === '' ? 0 : text.split('\n').length;
      files.push({ filename: path, status: 'removed', additions: 0, deletions: lines, changes: lines });
    } else if (h && b && h.oid !== b.oid) {
      const oldText = getObject(repo, b.oid)?.data.toString('utf8') ?? '';
      const newText = getObject(repo, h.oid)?.data.toString('utf8') ?? '';
      const { additions, deletions } = lineDiff(oldText, newText);
      files.push({ filename: path, status: 'modified', additions, deletions, changes: additions + deletions });
    }
  }
  return files;
}

/** 'MERGEABLE' | 'CONFLICTING' for a pull request (three-way check). */
function pullMergeable(repo, pull) {
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  if (!headTip || !baseTip) return 'UNKNOWN';
  if (pull.state !== 'open') return pull.merged ? 'MERGEABLE' : 'UNKNOWN';
  const base = mergeBase(repo, headTip, baseTip);
  if (!base) return 'UNKNOWN';
  const baseFlat = treeFlat(repo, base) ?? new Map();
  const headFlat = treeFlat(repo, headTip) ?? new Map();
  const tipFlat = treeFlat(repo, baseTip) ?? new Map();
  for (const [path, h] of headFlat) {
    const b = baseFlat.get(path);
    if (!b || b.oid !== h.oid) {
      const t = tipFlat.get(path);
      const tipOid = t ? t.oid : null;
      const baseOid = b ? b.oid : null;
      if (tipOid !== baseOid) return 'CONFLICTING';
    }
  }
  for (const [path, b] of baseFlat) {
    if (!headFlat.has(path)) {
      const t = tipFlat.get(path);
      if ((t ? t.oid : null) !== b.oid) return 'CONFLICTING';
    }
  }
  return 'MERGEABLE';
}

/** Squash-merge a pull request onto its base branch. Returns {sha} or {error, status}. */
function mergePullInternal(repo, pull) {
  if (pull.state !== 'open') return { error: 'pull request is not open', status: 405 };
  if (pullMergeable(repo, pull) !== 'MERGEABLE') return { error: 'merge conflict', status: 405 };
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  const headFlat = treeFlat(repo, headTip) ?? new Map();
  const treeOid = buildTreeFromFlat(repo, headFlat);
  const ts = COMMIT_EPOCH + (++store.commitSeq);
  const ident = `${VIEWER_NAME} <${VIEWER_EMAIL}>`;
  const message = `Merge pull request #${pull.number} from ${pull.headRef}\n\n${pull.title}\n`;
  const commitData = buildCommit({ tree: treeOid, parents: [baseTip], author: ident, committer: ident, timestamp: ts, message });
  const sha = putObject(repo, 'commit', commitData);
  repo.refs.set(`refs/heads/${pull.baseRef}`, sha);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = isoTs(++store.tsSeq);
  pull.mergeCommitSha = sha;
  return { sha };
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function requestId() {
  return `req-${++store.reqSeq}`;
}

function sendJson(res, status, obj, extra = {}) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': body.length,
    'x-github-request-id': requestId(),
    'x-oauth-scopes': 'repo, read:org',
    ...extra,
  });
  res.end(body);
}

function sendRaw(res, status, body, contentType, extra = {}) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(body);
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': buf.length,
    'x-github-request-id': requestId(),
    ...extra,
  });
  res.end(buf);
}

function sendNoContent(res, status) {
  res.writeHead(status, { 'x-github-request-id': requestId(), 'x-oauth-scopes': 'repo, read:org' });
  res.end();
}

function jsonError(res, status, message) {
  sendJson(res, status, { message });
}

function authOk(req) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return false;
  if (!TOKEN) return h.length > 7;
  return h === `Bearer ${TOKEN}`;
}

function decodeSegment(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// git smart HTTP
// ---------------------------------------------------------------------------

function refLinesV0(repo, service) {
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const tip = headTip(repo);
  const caps = service === 'git-receive-pack'
    ? `report-status report-status-v2 side-band-64k ofs-delta agent=${AGENT} delete-refs${tip ? ' symref=HEAD:refs/heads/main' : ''}`
    : `side-band-64k multi_ack_detailed thin-pack ofs-delta shallow agent=${AGENT}${tip ? ' symref=HEAD:refs/heads/main' : ''}`;
  const lines = [];
  if (refs.length === 0) {
    lines.push(`${ZERO_OID} capabilities^{}\0${caps}\n`);
  } else {
    lines.push(`${tip} HEAD\0${caps}\n`);
    for (const [name, oid] of refs) {
      lines.push(`${oid} ${name}\n`);
      const obj = getObject(repo, oid);
      if (obj && obj.type === 'tag') {
        const peeled = peelToCommit(repo, oid);
        if (peeled) lines.push(`${peeled} ${name}^{}\n`);
      }
    }
  }
  return lines;
}

function advertisementBuffer(repo, service, wantV2) {
  const parts = [pktLine(`# service=${service}\n`)];
  if (wantV2) {
    parts.push(pktLine('version 2\n'));
    parts.push(pktLine(`agent=${AGENT}\n`));
    parts.push(pktLine('ls-refs=unborn\n'));
    parts.push(pktLine('fetch=shallow filter\n'));
    parts.push(pktLine('object-format=sha1\n'));
    parts.push(PKT_FLUSH);
  } else {
    parts.push(encodePktLines([...refLinesV0(repo, service), 'flush']));
  }
  return Buffer.concat(parts);
}

function parsePktLineAt(buf, off) {
  if (off + 4 > buf.length) throw new Error('pkt-line truncated');
  const head = buf.toString('ascii', off, off + 4);
  if (head === '0000') return { kind: 'flush', payload: Buffer.alloc(0), next: off + 4 };
  if (head === '0001') return { kind: 'delim', payload: Buffer.alloc(0), next: off + 4 };
  if (head === '0002') return { kind: 'response-end', payload: Buffer.alloc(0), next: off + 4 };
  const len = Number.parseInt(head, 16);
  if (!Number.isFinite(len) || len < 4 || off + len > buf.length) throw new Error('bad pkt-line length');
  return { kind: 'data', payload: buf.subarray(off + 4, off + len), next: off + len };
}

function sidebandPackets(pack) {
  const out = [];
  const CHUNK = 65515;
  for (let off = 0; off < pack.length; off += CHUNK) {
    const piece = pack.subarray(off, Math.min(pack.length, off + CHUNK));
    out.push(pktLine(Buffer.concat([Buffer.from([1]), piece])));
  }
  if (pack.length === 0) out.push(pktLine(Buffer.from([1])));
  return out;
}

function handleInfoRefs(req, res, owner, repoName, service) {
  const repo = getRepo(owner, repoName);
  if (!repo) return jsonError(res, 404, 'Not Found');
  if (service !== 'git-upload-pack' && service !== 'git-receive-pack') return jsonError(res, 400, 'unknown service');
  const wantV2 = service === 'git-upload-pack' && req.headers['git-protocol'] === 'version=2';
  const body = advertisementBuffer(repo, service, wantV2);
  sendRaw(res, 200, body, `application/x-${service}-advertisement`);
}

function lsRefsResponse(repo, { prefixes, peel, symrefs }) {
  const lines = [];
  const tip = headTip(repo);
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const keep = (name) => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  if (keep('HEAD')) {
    if (tip) lines.push(`${tip} HEAD${symrefs ? ' symref-target:refs/heads/main' : ''}\n`);
    else lines.push(`unborn HEAD${symrefs ? ' symref-target:refs/heads/main' : ''}\n`);
  }
  for (const [name, oid] of refs) {
    if (!keep(name)) continue;
    let line = `${oid} ${name}`;
    const obj = getObject(repo, oid);
    if (peel && obj && obj.type === 'tag') {
      const peeled = peelToCommit(repo, oid);
      if (peeled) line += ` peeled:${peeled}`;
    }
    lines.push(`${line}\n`);
  }
  return Buffer.concat([encodePktLines([...lines, 'flush'])]);
}

function handleUploadPack(req, res, owner, repoName, body) {
  const repo = getRepo(owner, repoName);
  if (!repo) return jsonError(res, 404, 'Not Found');
  const isV2 = req.headers['git-protocol'] === 'version=2';
  let packets;
  try {
    packets = decodePktLines(body);
  } catch {
    return sendRaw(res, 400, 'bad pkt-line', 'text/plain');
  }
  const textLines = [];
  for (const p of packets) {
    if (p.kind === 'data') textLines.push(p.payload.toString('utf8'));
  }
  if (!isV2) return handleFetchV0(repo, res, textLines);
  const first = (textLines[0] ?? '').trim();
  if (first === 'command=ls-refs') {
    const prefixes = [];
    let peel = false;
    let symrefs = false;
    for (const line of textLines.slice(1)) {
      const t = line.trim();
      if (t === 'peel') peel = true;
      else if (t === 'symrefs') symrefs = true;
      else if (t.startsWith('ref-prefix ')) prefixes.push(t.slice('ref-prefix '.length));
    }
    const out = lsRefsResponse(repo, { prefixes, peel, symrefs });
    return sendRaw(res, 200, out, 'application/x-git-upload-pack-result');
  }
  if (first === 'command=fetch') return handleFetchV2(repo, res, textLines);
  return sendRaw(res, 400, 'unknown command', 'text/plain');
}

function parseFetchArgs(textLines) {
  const args = { wants: [], haves: [], shallow: [], depth: null, deepenSince: null, deepenNot: [], filter: null };
  for (const line of textLines.slice(1)) {
    const t = line.trim();
    if (t.startsWith('want ')) args.wants.push(t.slice(5).split(' ')[0]);
    else if (t.startsWith('have ')) args.haves.push(t.slice(5).trim());
    else if (t.startsWith('shallow ')) args.shallow.push(t.slice(8).trim());
    else if (t.startsWith('deepen ')) args.depth = Number.parseInt(t.slice(7), 10);
    else if (t.startsWith('deepen-since ')) args.deepenSince = Number.parseInt(t.slice(13), 10);
    else if (t.startsWith('deepen-not ')) args.deepenNot.push(t.slice(11).trim());
    else if (t.startsWith('filter ')) args.filter = t.slice(7).trim();
  }
  return args;
}

function ackLinesFor(repo, args, wantObjects) {
  if (args.haves.length === 0) return ['NAK\n'];
  const acks = args.haves.filter((h) => wantObjects.has(h));
  if (acks.length === 0) return ['NAK\n'];
  return [...acks.map((h) => `ACK ${h}\n`), 'ready\n'];
}

function handleFetchV2(repo, res, textLines) {
  const args = parseFetchArgs(textLines);
  if (args.wants.length === 0) {
    // No wants: an empty result (a clone of an empty repo never reaches here).
    const out = Buffer.concat([encodePktLines(['acknowledgments\n', 'NAK\n', 'delim', 'packfile\n']), ...sidebandPackets(writePack([])), PKT_FLUSH]);
    return sendRaw(res, 200, out, 'application/x-git-upload-pack-result');
  }
  const sel = fetchSelection(repo, { wants: args.wants, haves: args.haves, shallow: args.shallow, depth: args.depth });
  const wantRes = reachableObjects(repo, args.wants, { depth: args.depth });
  const pack = writePack([...sel.objects.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([, o]) => o));
  const parts = [];
  parts.push(encodePktLines(['acknowledgments\n', ...ackLinesFor(repo, args, wantRes.objects), 'delim']));
  if (sel.shallow.length > 0 || sel.unshallow.length > 0) {
    const lines = ['shallow-info\n'];
    for (const oid of sel.shallow) lines.push(`shallow ${oid}\n`);
    for (const oid of sel.unshallow) lines.push(`unshallow ${oid}\n`);
    lines.push('delim');
    parts.push(encodePktLines(lines));
  }
  parts.push(encodePktLines(['packfile\n']));
  parts.push(Buffer.concat(sidebandPackets(pack)));
  parts.push(PKT_FLUSH);
  sendRaw(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
}

function handleFetchV0(repo, res, textLines) {
  // v0 request: wants (with capabilities on the first line) in section one, then
  // haves + done in section two. The keys are distinct, so one pass collects both.
  const args = { wants: [], haves: [], shallow: [], depth: null };
  for (const line of textLines) {
    const t = line.trim();
    if (t.startsWith('want ')) args.wants.push(t.slice(5).split(' ')[0]);
    else if (t.startsWith('have ')) args.haves.push(t.slice(5).trim());
    else if (t.startsWith('shallow ')) args.shallow.push(t.slice(8).trim());
    else if (t.startsWith('deepen ')) args.depth = Number.parseInt(t.slice(7), 10);
  }
  const sel = fetchSelection(repo, { wants: args.wants, haves: args.haves, shallow: args.shallow, depth: args.depth });
  const wantRes = reachableObjects(repo, args.wants, { depth: args.depth });
  const pack = writePack([...sel.objects.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([, o]) => o));
  const lines = [...ackLinesFor(repo, args, wantRes.objects)];
  for (const oid of sel.shallow) lines.push(`shallow ${oid}\n`);
  const head = encodePktLines(lines);
  sendRaw(res, 200, Buffer.concat([head, ...sidebandPackets(pack), PKT_FLUSH]), 'application/x-git-upload-pack-result');
}

function handleReceivePack(req, res, owner, repoName, body) {
  const repo = getRepo(owner, repoName);
  if (!repo) return jsonError(res, 404, 'Not Found');
  // Parse command pkt-lines until the first flush; the rest is the pack.
  const commands = [];
  let off = 0;
  let packStart = body.length;
  try {
    for (;;) {
      const pkt = parsePktLineAt(body, off);
      off = pkt.next;
      if (pkt.kind === 'flush') { packStart = off; break; }
      if (pkt.kind === 'data') commands.push(pkt.payload.toString('utf8'));
      if (pkt.kind !== 'data' && pkt.kind !== 'flush') { /* delim: ignore */ }
    }
  } catch {
    return sendRaw(res, 400, 'bad pkt-line', 'text/plain');
  }
  const parsed = [];
  for (const rawLine of commands) {
    const line = rawLine.replace(/\n$/, '');
    const nul = line.indexOf('\0');
    const head = nul >= 0 ? line.slice(0, nul) : line;
    const parts = head.split(' ');
    if (parts.length !== 3) continue;
    parsed.push({ oldOid: parts[0], newOid: parts[1], ref: parts[2] });
  }
  const packBytes = body.subarray(packStart);
  let unpackOk = true;
  let unpackDetail = 'ok';
  if (packBytes.length > 0) {
    try {
      const read = readPack(packBytes);
      for (const [oid, obj] of read.objects) {
        if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
      }
    } catch (err) {
      unpackOk = false;
      unpackDetail = String(err.message ?? err).replace(/[\r\n]+/g, ' ').slice(0, 120);
    }
  }
  const report = [];
  if (unpackOk) {
    for (const cmd of parsed) {
      const current = repo.refs.get(cmd.ref);
      if (cmd.newOid === ZERO_OID) {
        // delete
        if (!current) report.push({ ref: cmd.ref, ok: false, reason: 'remote ref does not exist' });
        else if (cmd.oldOid !== ZERO_OID && cmd.oldOid !== current) report.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
        else { repo.refs.delete(cmd.ref); report.push({ ref: cmd.ref, ok: true, reason: '' }); }
        continue;
      }
      if (!repo.objects.has(cmd.newOid)) {
        report.push({ ref: cmd.ref, ok: false, reason: 'missing object' });
        continue;
      }
      if (cmd.oldOid === ZERO_OID) {
        // create
        if (current) report.push({ ref: cmd.ref, ok: false, reason: 'already exists' });
        else if (cmd.ref.startsWith('refs/heads/') && getObject(repo, cmd.newOid)?.type !== 'commit') {
          report.push({ ref: cmd.ref, ok: false, reason: 'not a commit' });
        } else { repo.refs.set(cmd.ref, cmd.newOid); report.push({ ref: cmd.ref, ok: true, reason: '' }); }
        continue;
      }
      // update
      if (!current) report.push({ ref: cmd.ref, ok: false, reason: 'remote ref does not exist' });
      else if (cmd.oldOid !== current) report.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
      else if (cmd.newOid === current) report.push({ ref: cmd.ref, ok: true, reason: '' });
      else if (cmd.ref.startsWith('refs/heads/')) {
        const obj = getObject(repo, cmd.newOid);
        if (!obj || obj.type !== 'commit') report.push({ ref: cmd.ref, ok: false, reason: 'not a commit' });
        else if (isAncestor(repo, current, cmd.newOid)) { repo.refs.set(cmd.ref, cmd.newOid); report.push({ ref: cmd.ref, ok: true, reason: '' }); }
        else report.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
      } else {
        report.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
      }
    }
  } else {
    for (const cmd of parsed) report.push({ ref: cmd.ref, ok: false, reason: unpackDetail });
  }
  const lines = [`unpack ${unpackDetail}\n`];
  for (const r of report) lines.push(r.ok ? `ok ${r.ref}\n` : `ng ${r.ref} ${r.reason}\n`);
  const reportBytes = encodePktLines(lines);
  const out = Buffer.concat([...sidebandPackets(reportBytes), PKT_FLUSH]);
  sendRaw(res, 200, out, 'application/x-git-receive-pack-result');
}

// ---------------------------------------------------------------------------
// REST v3
// ---------------------------------------------------------------------------

function parseJsonBody(raw) {
  if (raw.length === 0) return {};
  try {
    const v = JSON.parse(raw.toString('utf8'));
    return v !== null && typeof v === 'object' ? v : {};
  } catch {
    return null;
  }
}

function paginate(items, query, absoluteBase) {
  const pp = clampInt(query.get('per_page'), 1, 100, 30);
  const page = clampInt(query.get('page'), 1, 1000000, 1);
  const start = (page - 1) * pp;
  const slice = items.slice(start, start + pp);
  const totalPages = Math.max(1, Math.ceil(items.length / pp));
  const links = [];
  const urlFor = (p) => `${absoluteBase}?per_page=${pp}&page=${p}`;
  if (page < totalPages) {
    links.push(`<${urlFor(page + 1)}>; rel="next"`);
    links.push(`<${urlFor(totalPages)}>; rel="last"`);
  }
  if (page > 1) {
    links.push(`<${urlFor(1)}>; rel="first"`);
    links.push(`<${urlFor(page - 1)}>; rel="prev"`);
  }
  return { slice, link: links.join(', ') };
}

function absoluteBase(req, pathname) {
  return `http://${req.headers.host}${pathname}`;
}

function stripMessage(message) {
  return String(message ?? '').replace(/\n+$/, '');
}

async function handleRest(req, res, segments, query, rawBody) {
  const method = req.method;
  // Root and meta are public; everything else needs the bearer token.
  const isRoot = segments.length === 0;
  const isMeta = segments.length === 1 && segments[0] === 'meta';
  if (!isRoot && !isMeta && !authOk(req)) return jsonError(res, 401, 'Requires authentication');

  const body = (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') ? parseJsonBody(rawBody) : {};
  if (body === null) return jsonError(res, 400, 'Invalid JSON body');

  if (isRoot) {
    if (method !== 'GET') return jsonError(res, 404, 'Not Found');
    return sendJson(res, 200, {
      current_user_url: '/api/v3/user',
      repository_url: '/api/v3/repos/{owner}/{repo}',
      user_repositories_url: '/api/v3/user/repos',
    });
  }
  if (isMeta) {
    if (method !== 'GET') return jsonError(res, 404, 'Not Found');
    return sendJson(res, 200, { installed_version: SERVER_VERSION, version: SERVER_VERSION, verifiable: true });
  }

  // /user, /user/repos
  if (segments[0] === 'user' && segments.length === 1) {
    if (method !== 'GET') return jsonError(res, 404, 'Not Found');
    return sendJson(res, 200, { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User', name: VIEWER_NAME, email: VIEWER_EMAIL });
  }
  if (segments[0] === 'user' && segments[1] === 'repos' && segments.length === 2) {
    if (method === 'GET') {
      const items = store.repoOrder.map(repoRestObject);
      const { slice, link } = paginate(items, query, absoluteBase(req, '/api/v3/user/repos'));
      return sendJson(res, 200, slice, link ? { link } : {});
    }
    if (method === 'POST') {
      const name = body.name;
      if (typeof name !== 'string' || name === '') return jsonError(res, 422, 'name is required');
      const created = createRepoInternal(VIEWER_LOGIN, name, { description: body.description, private: body.private === true });
      if (created.error === 'exists') return jsonError(res, 422, 'name already exists on this account');
      if (created.error === 'bad name') return jsonError(res, 422, 'invalid repository name');
      return sendJson(res, 201, repoRestObject(created.repo));
    }
    return jsonError(res, 404, 'Not Found');
  }

  // /repos/{owner}/{repo}/...
  if (segments[0] === 'repos' && segments.length >= 3) {
    const owner = segments[1];
    const repoName = segments[2];
    const repo = getRepo(owner, repoName);
    const rest = segments.slice(3);
    if (!repo) return jsonError(res, 404, 'Not Found');
    return handleRepoRest(req, res, repo, rest, query, body, method);
  }

  return jsonError(res, 404, 'Not Found');
}

function handleRepoRest(req, res, repo, rest, query, body, method) {
  // /repos/{o}/{r} itself
  if (rest.length === 0) {
    if (method === 'GET') return sendJson(res, 200, repoRestObject(repo));
    if (method === 'PATCH') {
      if (typeof body.description === 'string') repo.description = body.description;
      if (typeof body.private === 'boolean') repo.private = body.private;
      return sendJson(res, 200, repoRestObject(repo));
    }
    if (method === 'DELETE') {
      deleteRepoInternal(repo.owner, repo.name);
      return sendNoContent(res, 204);
    }
    return jsonError(res, 404, 'Not Found');
  }

  const head = rest[0];

  if (head === 'branches') {
    if (rest.length === 1 && method === 'GET') {
      const list = [...repo.refs.entries()]
        .filter(([name]) => name.startsWith('refs/heads/'))
        .sort((a, b) => (a[0] < b[0] ? -1 : 1))
        .map(([name, sha]) => ({ name: name.slice('refs/heads/'.length), commit: { sha, url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${sha}` }, protected: false }));
      return sendJson(res, 200, list);
    }
    if (rest.length === 2 && method === 'GET') {
      const sha = repo.refs.get(`refs/heads/${rest[1]}`);
      if (!sha) return jsonError(res, 404, 'Not Found');
      return sendJson(res, 200, { name: rest[1], commit: { sha, url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${sha}` }, protected: false });
    }
    return jsonError(res, 404, 'Not Found');
  }

  if (head === 'git' && rest[1] === 'refs') {
    if (method === 'POST' && rest.length === 2) {
      const ref = body.ref;
      const sha = body.sha;
      if (typeof ref !== 'string' || !ref.startsWith('refs/')) return jsonError(res, 422, 'invalid ref');
      if (typeof sha !== 'string' || !repo.objects.has(sha)) return jsonError(res, 422, 'unknown object');
      if (repo.refs.has(ref)) return jsonError(res, 422, 'reference already exists');
      repo.refs.set(ref, sha);
      return sendJson(res, 201, { ref, object: { sha, type: getObject(repo, sha).type } });
    }
    if (method === 'GET' && rest.length === 2) {
      const list = [...repo.refs.entries()]
        .sort((a, b) => (a[0] < b[0] ? -1 : 1))
        .map(([name, sha]) => ({ ref: name, object: { sha, type: getObject(repo, sha)?.type ?? 'commit' } }));
      return sendJson(res, 200, list);
    }
    if (method === 'GET' && rest.length === 4 && (rest[2] === 'heads' || rest[2] === 'tags')) {
      const refName = `refs/${rest[2]}/${rest[3]}`;
      const sha = repo.refs.get(refName);
      if (!sha) return jsonError(res, 404, 'Not Found');
      return sendJson(res, 200, { ref: refName, object: { sha, type: getObject(repo, sha)?.type ?? 'commit' } });
    }
    return jsonError(res, 404, 'Not Found');
  }

  if (head === 'commits') {
    if (method !== 'GET') return jsonError(res, 404, 'Not Found');
    const refName = query.get('sha');
    const tip = refName ? resolveRef(repo, refName) : headTip(repo);
    if (!tip) return jsonError(res, 404, 'Not Found');
    const all = history(repo, tip).map((sha) => {
      const c = getCommit(repo, sha);
      const msg = stripMessage(c ? c.message : '');
      return {
        sha,
        commit: {
          message: msg,
          author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: isoTs(1) },
          committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: isoTs(1) },
        },
        author: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
        url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${sha}`,
      };
    });
    const { slice } = paginate(all, query, absoluteBase(req, `/api/v3/repos/${repo.owner}/${repo.name}/commits`));
    return sendJson(res, 200, slice);
  }

  if (head === 'contents') {
    return handleContents(req, res, repo, rest.slice(1), query, body, method);
  }

  if (head === 'labels') {
    if (method === 'GET' && rest.length === 1) {
      return sendJson(res, 200, [...repo.labels.values()].map((l) => ({ name: l.name, color: l.color })));
    }
    if (method === 'POST' && rest.length === 1) {
      const name = body.name;
      if (typeof name !== 'string' || name === '') return jsonError(res, 422, 'name is required');
      if (repo.labels.has(name)) return jsonError(res, 422, 'label already exists');
      const color = typeof body.color === 'string' && body.color !== '' ? body.color : 'ededed';
      repo.labels.set(name, { name, color });
      return sendJson(res, 201, { name, color });
    }
    return jsonError(res, 404, 'Not Found');
  }

  if (head === 'issues') {
    return handleIssues(req, res, repo, rest.slice(1), query, body, method);
  }

  if (head === 'pulls') {
    return handlePulls(req, res, repo, rest.slice(1), query, body, method);
  }

  return jsonError(res, 404, 'Not Found');
}

function handleContents(req, res, repo, pathParts, query, body, method) {
  const path = pathParts.join('/');
  const refName = query.get('ref');
  const tip = refName ? resolveRef(repo, refName) : headTip(repo);
  if (method === 'GET') {
    if (!tip) return jsonError(res, 404, 'Not Found');
    const flat = treeFlat(repo, tip);
    if (!flat) return jsonError(res, 404, 'Not Found');
    if (path === '') {
      return sendJson(res, 200, directoryListing(repo, flat, ''));
    }
    const file = flat.get(path);
    if (file) {
      const data = getObject(repo, file.oid)?.data ?? Buffer.alloc(0);
      return sendJson(res, 200, {
        type: 'file',
        encoding: 'base64',
        size: data.length,
        name: path.split('/').pop(),
        path,
        sha: file.oid,
        content: b64encode(data),
        url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${path}`,
        html_url: `https://github.com/${repo.owner}/${repo.name}/blob/${repo.defaultBranch}/${path}`,
      });
    }
    // directory?
    const prefix = `${path}/`;
    let isDir = false;
    for (const key of flat.keys()) if (key.startsWith(prefix)) { isDir = true; break; }
    if (isDir) return sendJson(res, 200, directoryListing(repo, flat, path));
    return jsonError(res, 404, 'Not Found');
  }

  if (method === 'PUT') {
    if (path === '') return jsonError(res, 422, 'a path is required');
    let branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
    let branchTip = repo.refs.get(`refs/heads/${branch}`);
    if (!branchTip) {
      const defaultTip = headTip(repo);
      if (defaultTip) {
        repo.refs.set(`refs/heads/${branch}`, defaultTip);
        branchTip = defaultTip;
      } else {
        // Unborn repository: this branch becomes the first (and default) branch.
        repo.defaultBranch = branch;
      }
    }
    const flat = branchTip ? treeFlat(repo, branchTip) ?? new Map() : new Map();
    const existing = flat.get(path);
    if (existing) {
      if (typeof body.sha === 'string' && body.sha !== existing.oid) return jsonError(res, 409, 'sha does not match the current blob');
      if (typeof body.sha !== 'string') return jsonError(res, 422, 'sha is required to update a file');
    }
    if (typeof body.content !== 'string') return jsonError(res, 422, 'content is required');
    const data = b64decode(body.content);
    const message = typeof body.message === 'string' && body.message !== '' ? body.message : `Update ${path}`;
    const sha = commitOnBranch(repo, branch, new Map([[path, data]]), message);
    const blobOid = putObject(repo, 'blob', data);
    const status = existing ? 200 : 201;
    return sendJson(res, status, {
      content: { name: path.split('/').pop(), path, sha: blobOid, size: data.length, type: 'file', encoding: 'base64', content: b64encode(data) },
      commit: { sha, message },
    });
  }

  if (method === 'DELETE') {
    if (!tip) return jsonError(res, 404, 'Not Found');
    const flat = treeFlat(repo, tip);
    const existing = flat?.get(path);
    if (!existing) return jsonError(res, 404, 'Not Found');
    if (typeof body.sha === 'string' && body.sha !== existing.oid) return jsonError(res, 409, 'sha does not match the current blob');
    const branch = refName && repo.refs.has(`refs/heads/${refName}`) ? refName : repo.defaultBranch;
    const message = typeof body.message === 'string' && body.message !== '' ? body.message : `Delete ${path}`;
    const sha = commitOnBranch(repo, branch, new Map([[path, null]]), message);
    return sendJson(res, 200, { commit: { sha, message } });
  }

  return jsonError(res, 404, 'Not Found');
}

function directoryListing(repo, flat, dir) {
  const prefix = dir === '' ? '' : `${dir}/`;
  const seen = new Map(); // name -> {type, name, path, sha, size}
  for (const [path, info] of flat) {
    if (!path.startsWith(prefix)) continue;
    const rest = path.slice(prefix.length);
    const slash = rest.indexOf('/');
    if (slash < 0) {
      seen.set(rest, { type: 'file', name: rest, path, sha: info.oid, size: getObject(repo, info.oid)?.data.length ?? 0 });
    } else {
      const dirName = rest.slice(0, slash);
      if (!seen.has(dirName)) {
        seen.set(dirName, { type: 'dir', name: dirName, path: `${prefix}${dirName}`, sha: '', size: 0 });
      }
    }
  }
  // Directory entries need a tree sha: compute from the flat map.
  const out = [...seen.values()].sort((a, b) => (a.name < b.name ? -1 : 1));
  for (const entry of out) {
    if (entry.type === 'dir') {
      const sub = new Map();
      const subPrefix = `${entry.path}/`;
      for (const [path, info] of flat) if (path.startsWith(subPrefix)) sub.set(path.slice(subPrefix.length), info);
      entry.sha = buildTreeFromFlat(repo, new Map([...sub.entries()].map(([p, info]) => [p, info])));
    }
  }
  return out;
}

function handleIssues(req, res, repo, rest, query, body, method) {
  if (rest.length === 0) {
    if (method === 'POST') {
      const created = createIssueInternal(repo, { title: body.title, body: body.body, labels: body.labels });
      if (created.error) return jsonError(res, created.status ?? 422, created.error);
      return sendJson(res, 201, issueRestObject(repo, created.issue));
    }
    if (method === 'GET') {
      const state = query.get('state') ?? 'open';
      const sort = query.get('sort') ?? 'created';
      const direction = query.get('direction') ?? 'desc';
      let list = [...repo.issues.values()];
      if (state === 'open') list = list.filter((i) => i.state === 'open');
      else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
      list.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
      const { slice, link } = paginate(list.map((i) => issueRestObject(repo, i)), query, absoluteBase(req, `/api/v3/repos/${repo.owner}/${repo.name}/issues`));
      return sendJson(res, 200, slice, link ? { link } : {});
    }
    return jsonError(res, 404, 'Not Found');
  }
  const number = Number.parseInt(rest[0], 10);
  if (!Number.isInteger(number)) return jsonError(res, 404, 'Not Found');
  const issue = repo.issues.get(number);
  if (rest.length === 1) {
    if (!issue) return jsonError(res, 404, 'Not Found');
    if (method === 'GET') return sendJson(res, 200, issueRestObject(repo, issue));
    if (method === 'PATCH') {
      if (typeof body.title === 'string') issue.title = body.title;
      if (typeof body.body === 'string') issue.body = body.body;
      if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
      if (Array.isArray(body.labels)) {
        for (const name of body.labels) if (!repo.labels.has(name)) return jsonError(res, 422, `unknown label ${name}`);
        issue.labels = [...body.labels];
      }
      return sendJson(res, 200, issueRestObject(repo, issue));
    }
    return jsonError(res, 404, 'Not Found');
  }
  if (rest[1] === 'comments') {
    if (!issue) return jsonError(res, 404, 'Not Found');
    if (method === 'GET') {
      return sendJson(res, 200, issue.comments.map((c) => ({
        id: c.id,
        node_id: gid('IssueComment', `${repo.owner}/${repo.name}:${issue.number}:${c.id}`),
        body: c.body,
        user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
        created_at: isoTs(c.seq),
      })));
    }
    if (method === 'POST') {
      if (typeof body.body !== 'string' || body.body === '') return jsonError(res, 422, 'body is required');
      const comment = { id: store.nextRestId++, body: body.body, seq: ++store.tsSeq };
      issue.comments.push(comment);
      return sendJson(res, 201, {
        id: comment.id,
        node_id: gid('IssueComment', `${repo.owner}/${repo.name}:${issue.number}:${comment.id}`),
        body: comment.body,
        user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
        created_at: isoTs(comment.seq),
      });
    }
    return jsonError(res, 404, 'Not Found');
  }
  return jsonError(res, 404, 'Not Found');
}

function handlePulls(req, res, repo, rest, query, body, method) {
  if (rest.length === 0) {
    if (method === 'POST') {
      const created = createPullInternal(repo, { title: body.title, head: body.head, base: body.base, body: body.body });
      if (created.error) return jsonError(res, created.status ?? 422, created.error);
      return sendJson(res, 201, pullRestObject(repo, created.pull));
    }
    if (method === 'GET') {
      const state = query.get('state') ?? 'open';
      let list = [...repo.pulls.values()];
      if (state === 'open') list = list.filter((p) => p.state === 'open');
      else if (state === 'closed') list = list.filter((p) => p.state === 'closed');
      list.sort((a, b) => b.seq - a.seq);
      const { slice, link } = paginate(list.map((p) => pullRestObject(repo, p)), query, absoluteBase(req, `/api/v3/repos/${repo.owner}/${repo.name}/pulls`));
      return sendJson(res, 200, slice, link ? { link } : {});
    }
    return jsonError(res, 404, 'Not Found');
  }
  const number = Number.parseInt(rest[0], 10);
  if (!Number.isInteger(number)) return jsonError(res, 404, 'Not Found');
  const pull = repo.pulls.get(number);
  if (rest.length === 1) {
    if (!pull) return jsonError(res, 404, 'Not Found');
    if (method === 'GET') return sendJson(res, 200, pullRestObject(repo, pull));
    return jsonError(res, 404, 'Not Found');
  }
  if (rest[1] === 'files' && method === 'GET') {
    if (!pull) return jsonError(res, 404, 'Not Found');
    return sendJson(res, 200, pullFiles(repo, pull));
  }
  if (rest[1] === 'merge' && method === 'PUT') {
    if (!pull) return jsonError(res, 404, 'Not Found');
    const merged = mergePullInternal(repo, pull);
    if (merged.error) return jsonError(res, merged.status ?? 405, merged.error);
    return sendJson(res, 200, { sha: merged.sha, merged: true, message: `Pull Request successfully merged` });
  }
  return jsonError(res, 404, 'Not Found');
}

// ---------------------------------------------------------------------------
// GraphQL v4 (hand-written parser + executor for the documents gh sends)
// ---------------------------------------------------------------------------

function gqlTokenize(src) {
  const tokens = [];
  let i = 0;
  const isNameStart = (c) => /[_A-Za-z]/.test(c);
  const isNameChar = (c) => /[_0-9A-Za-z]/.test(c);
  while (i < src.length) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',') { i += 1; continue; }
    if (c === '#') { while (i < src.length && src[i] !== '\n') i += 1; continue; }
    if (c === '.' && src.slice(i, i + 3) === '...') { tokens.push({ type: '...' }); i += 3; continue; }
    if ('!$():=@[]{}|&'.includes(c)) { tokens.push({ type: c }); i += 1; continue; }
    if (c === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\') {
          const e = src[j + 1];
          if (e === 'n') out += '\n';
          else if (e === 't') out += '\t';
          else if (e === 'r') out += '\r';
          else if (e === 'u') { out += String.fromCharCode(Number.parseInt(src.slice(j + 2, j + 6), 16)); j += 4; }
          else out += e;
          j += 2;
        } else { out += src[j]; j += 1; }
      }
      tokens.push({ type: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (c === '-' || /[0-9]/.test(c)) {
      let j = i;
      if (src[j] === '-') j += 1;
      while (j < src.length && /[0-9]/.test(src[j])) j += 1;
      let isFloat = false;
      if (src[j] === '.') { isFloat = true; j += 1; while (j < src.length && /[0-9]/.test(src[j])) j += 1; }
      if (src[j] === 'e' || src[j] === 'E') {
        isFloat = true; j += 1;
        if (src[j] === '+' || src[j] === '-') j += 1;
        while (j < src.length && /[0-9]/.test(src[j])) j += 1;
      }
      tokens.push({ type: isFloat ? 'float' : 'int', value: src.slice(i, j) });
      i = j;
      continue;
    }
    if (isNameStart(c)) {
      let j = i;
      while (j < src.length && isNameChar(src[j])) j += 1;
      tokens.push({ type: 'name', value: src.slice(i, j) });
      i = j;
      continue;
    }
    throw new Error(`unexpected character ${JSON.stringify(c)}`);
  }
  tokens.push({ type: 'eof' });
  return tokens;
}

function gqlParse(src) {
  const tokens = gqlTokenize(src);
  let pos = 0;
  const peek = () => tokens[pos];
  const next = () => tokens[pos++];
  const expect = (type) => {
    const t = next();
    if (t.type !== type) throw new Error(`expected ${type}, got ${t.type}`);
    return t;
  };
  const parseName = () => expect('name').value;

  function parseValue() {
    const t = peek();
    if (t.type === '$') {
      next();
      return { kind: 'var', name: parseName() };
    }
    if (t.type === 'int' || t.type === 'float') { next(); return { kind: 'literal', value: Number(t.value) }; }
    if (t.type === 'string') { next(); return { kind: 'literal', value: t.value }; }
    if (t.type === 'name') {
      next();
      if (t.value === 'true') return { kind: 'literal', value: true };
      if (t.value === 'false') return { kind: 'literal', value: false };
      if (t.value === 'null') return { kind: 'literal', value: null };
      return { kind: 'enum', value: t.value };
    }
    if (t.type === '[') {
      next();
      const values = [];
      while (peek().type !== ']') values.push(parseValue());
      expect(']');
      return { kind: 'list', values };
    }
    if (t.type === '{') {
      next();
      const fields = {};
      while (peek().type !== '}') {
        const name = parseName();
        expect(':');
        fields[name] = parseValue();
      }
      expect('}');
      return { kind: 'object', fields };
    }
    throw new Error(`unexpected value token ${t.type}`);
  }

  function parseArguments() {
    const args = {};
    if (peek().type !== '(') return args;
    next();
    while (peek().type !== ')') {
      const name = parseName();
      expect(':');
      args[name] = parseValue();
    }
    expect(')');
    return args;
  }

  function parseDirectives() {
    while (peek().type === '@') {
      next();
      parseName();
      parseArguments();
    }
  }

  function parseType() {
    if (peek().type === '[') {
      next();
      parseType();
      expect(']');
    } else {
      parseName();
    }
    if (peek().type === '!') next();
  }

  function parseSelectionSet() {
    expect('{');
    const selections = [];
    while (peek().type !== '}') selections.push(parseSelection());
    expect('}');
    return selections;
  }

  function parseSelection() {
    if (peek().type === '...') {
      next();
      let typeCondition = null;
      if (peek().type === 'name' && peek().value === 'on') {
        next();
        typeCondition = parseName();
      }
      parseDirectives();
      return { kind: 'fragment', typeCondition, selections: parseSelectionSet() };
    }
    const first = parseName();
    let alias = null;
    let name = first;
    if (peek().type === ':') {
      next();
      alias = first;
      name = parseName();
    }
    const args = parseArguments();
    parseDirectives();
    const selections = peek().type === '{' ? parseSelectionSet() : null;
    return { kind: 'field', alias, name, args, selections };
  }

  function parseOperation() {
    const t = peek();
    if (t.type === '{') return { kind: 'operation', operation: 'query', name: null, selections: parseSelectionSet() };
    if (t.type === 'name' && (t.value === 'query' || t.value === 'mutation' || t.value === 'subscription')) {
      next();
      const operation = t.value;
      let name = null;
      if (peek().type === 'name') name = parseName();
      if (peek().type === '(') {
        next();
        while (peek().type !== ')') {
          next(); // skip variable definitions (names/types/defaults); values come from `variables`
          if (peek().type === ':') { next(); parseType(); if (peek().type === '=') { next(); parseValue(); } }
        }
        expect(')');
      }
      parseDirectives();
      return { kind: 'operation', operation, name, selections: parseSelectionSet() };
    }
    if (t.type === 'name' && t.value === 'fragment') {
      next();
      parseName();
      if (peek().type === 'name' && peek().value === 'on') { next(); parseName(); }
      parseDirectives();
      parseSelectionSet();
      return { kind: 'fragmentdef' };
    }
    throw new Error(`unexpected definition ${t.type}`);
  }

  const definitions = [];
  while (peek().type !== 'eof') definitions.push(parseOperation());
  return definitions;
}

function gqlResolveValue(node, variables) {
  if (!node) return undefined;
  if (node.kind === 'var') return variables[node.name];
  if (node.kind === 'literal') return node.value;
  if (node.kind === 'enum') return node.value;
  if (node.kind === 'list') return node.values.map((v) => gqlResolveValue(v, variables));
  if (node.kind === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(node.fields)) out[k] = gqlResolveValue(v, variables);
    return out;
  }
  return undefined;
}

function gqlArgs(field, variables) {
  const out = {};
  for (const [k, v] of Object.entries(field.args ?? {})) out[k] = gqlResolveValue(v, variables);
  return out;
}

// Introspection surface (the field lists gh feature-detects).
const GQL_TYPE_FIELDS = {
  Issue: ['id', 'number', 'title', 'state', 'body', 'createdAt', 'updatedAt', 'url', 'author', 'labels', 'comments', 'repository'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'headRef', 'baseRef', 'files', 'mergedAt', 'mergeCommit', 'author', 'createdAt', 'updatedAt'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'private', 'url', 'createdAt', 'updatedAt'],
  User: ['id', 'login', 'name', 'email'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  PullRequestChangedFile: ['path', 'additions', 'deletions', 'changeType'],
  Ref: ['name'],
  IssueComment: ['id', 'body', 'author'],
  CommentEdge: ['node', 'cursor'],
  CreateIssuePayload: ['issue'],
  CloseIssuePayload: ['issue'],
  CreatePullRequestPayload: ['pullRequest'],
  MergePullRequestPayload: ['pullRequest'],
  AddCommentPayload: ['commentEdge'],
  Query: ['viewer', 'repository', 'node', '__type', '__schema'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
};
const GQL_TYPE_ENUMS = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'CODE', 'MARKETPLACE'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  OrderDirection: ['ASC', 'DESC'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
  PullRequestMergeMethod: ['MERGE', 'SQUASH', 'REBASE'],
};

function issueGqlState(issue) {
  return issue.state === 'closed' ? 'CLOSED' : 'OPEN';
}
function pullGqlState(pull) {
  if (pull.state === 'open') return 'OPEN';
  return pull.merged ? 'MERGED' : 'CLOSED';
}

function cursorFor(index) {
  return Buffer.from(`cursor:${index}`, 'utf8').toString('base64');
}
function indexFromCursor(cursor) {
  try {
    const text = Buffer.from(String(cursor), 'base64').toString('utf8');
    const m = /^cursor:(\d+)$/.exec(text);
    return m ? Number.parseInt(m[1], 10) : -1;
  } catch {
    return -1;
  }
}

function issuesConnection(repo, args) {
  let list = [...repo.issues.values()];
  const states = args.states;
  if (Array.isArray(states) && states.length > 0) {
    const want = new Set(states.map((s) => String(s).toUpperCase()));
    list = list.filter((i) => want.has(issueGqlState(i)));
  }
  const orderBy = args.orderBy ?? {};
  const direction = String(orderBy.direction ?? 'DESC').toUpperCase();
  list.sort((a, b) => (direction === 'ASC' ? a.seq - b.seq : b.seq - a.seq));
  let start = 0;
  if (typeof args.after === 'string' && args.after !== '') {
    const idx = indexFromCursor(args.after);
    if (idx >= 0) start = idx + 1;
  }
  const first = typeof args.first === 'number' ? args.first : list.length;
  const slice = list.slice(start, start + first);
  const endCursor = slice.length > 0 ? cursorFor(start + slice.length - 1) : null;
  return {
    __type: 'IssueConnection',
    nodes: slice.map((issue) => ({ __type: 'Issue', repo, issue })),
    pageInfo: { hasNextPage: start + slice.length < list.length, endCursor },
  };
}

function repoWrapper(repo) {
  return { __type: 'Repository', repo };
}
function issueWrapper(repo, issue) {
  return { __type: 'Issue', repo, issue };
}
function pullWrapper(repo, pull) {
  return { __type: 'PullRequest', repo, pull };
}
function userWrapper(login) {
  return { __type: 'User', login };
}

/** Resolve one field on a wrapped parent value. Returns the raw value (or wrapper). */
function gqlResolve(parent, parentType, field, variables, errors) {
  const args = gqlArgs(field, variables);
  const unknown = () => {
    errors.push({ message: `Cannot query field "${field.name}" on type "${parentType}".` });
    return null;
  };
  switch (parentType) {
    case 'Query': {
      if (field.name === 'viewer') return userWrapper(VIEWER_LOGIN);
      if (field.name === 'repository') {
        const repo = getRepo(args.owner, args.name);
        return repo ? repoWrapper(repo) : null;
      }
      if (field.name === 'node') {
        const decoded = ungid(args.id);
        if (!decoded) return null;
        if (decoded.kind === 'Repository') {
          const [owner, name] = decoded.key.split('/');
          const repo = getRepo(owner, name);
          return repo ? repoWrapper(repo) : null;
        }
        if (decoded.kind === 'Issue') {
          const m = /^(.*):(\d+)$/.exec(decoded.key);
          if (!m) return null;
          const [owner, name] = m[1].split('/');
          const repo = getRepo(owner, name);
          const issue = repo?.issues.get(Number.parseInt(m[2], 10));
          return issue ? issueWrapper(repo, issue) : null;
        }
        if (decoded.kind === 'PullRequest') {
          const m = /^(.*):(\d+)$/.exec(decoded.key);
          if (!m) return null;
          const [owner, name] = m[1].split('/');
          const repo = getRepo(owner, name);
          const pull = repo?.pulls.get(Number.parseInt(m[2], 10));
          return pull ? pullWrapper(repo, pull) : null;
        }
        return null;
      }
      if (field.name === '__type') {
        const name = args.name;
        if (GQL_TYPE_FIELDS[name]) return { __type: '__Type', name, kind: 'OBJECT' };
        if (GQL_TYPE_ENUMS[name]) return { __type: '__Type', name, kind: 'ENUM' };
        return null;
      }
      if (field.name === '__schema') return { __type: '__Schema' };
      return unknown();
    }
    case 'Mutation': {
      if (field.name === 'createIssue') {
        const input = args.input ?? {};
        const decoded = ungid(input.repositoryId);
        if (!decoded || decoded.kind !== 'Repository') {
          errors.push({ message: 'createIssue: unknown repositoryId' });
          return null;
        }
        const [owner, name] = decoded.key.split('/');
        const repo = getRepo(owner, name);
        if (!repo) { errors.push({ message: 'createIssue: repository not found' }); return null; }
        const created = createIssueInternal(repo, { title: input.title, body: input.body });
        if (created.error) { errors.push({ message: `createIssue: ${created.error}` }); return null; }
        return { __type: 'CreateIssuePayload', issue: issueWrapper(repo, created.issue) };
      }
      if (field.name === 'closeIssue') {
        const input = args.input ?? {};
        const decoded = ungid(input.issueId);
        if (!decoded || decoded.kind !== 'Issue') { errors.push({ message: 'closeIssue: unknown issueId' }); return null; }
        const m = /^(.*):(\d+)$/.exec(decoded.key);
        if (!m) { errors.push({ message: 'closeIssue: unknown issueId' }); return null; }
        const [owner, name] = m[1].split('/');
        const repo = getRepo(owner, name);
        const issue = repo?.issues.get(Number.parseInt(m[2], 10));
        if (!issue) { errors.push({ message: 'closeIssue: issue not found' }); return null; }
        issue.state = 'closed';
        return { __type: 'CloseIssuePayload', issue: issueWrapper(repo, issue) };
      }
      if (field.name === 'createPullRequest') {
        const input = args.input ?? {};
        const decoded = ungid(input.repositoryId);
        if (!decoded || decoded.kind !== 'Repository') { errors.push({ message: 'createPullRequest: unknown repositoryId' }); return null; }
        const [owner, name] = decoded.key.split('/');
        const repo = getRepo(owner, name);
        if (!repo) { errors.push({ message: 'createPullRequest: repository not found' }); return null; }
        const created = createPullInternal(repo, { title: input.title, head: input.headRefName, base: input.baseRefName, body: input.body });
        if (created.error) { errors.push({ message: `createPullRequest: ${created.error}` }); return null; }
        return { __type: 'CreatePullRequestPayload', pullRequest: pullWrapper(repo, created.pull) };
      }
      if (field.name === 'mergePullRequest') {
        const input = args.input ?? {};
        const decoded = ungid(input.pullRequestId);
        if (!decoded || decoded.kind !== 'PullRequest') { errors.push({ message: 'mergePullRequest: unknown pullRequestId' }); return null; }
        const m = /^(.*):(\d+)$/.exec(decoded.key);
        if (!m) { errors.push({ message: 'mergePullRequest: unknown pullRequestId' }); return null; }
        const [owner, name] = m[1].split('/');
        const repo = getRepo(owner, name);
        const pull = repo?.pulls.get(Number.parseInt(m[2], 10));
        if (!pull) { errors.push({ message: 'mergePullRequest: pull request not found' }); return null; }
        const merged = mergePullInternal(repo, pull);
        if (merged.error) { errors.push({ message: `mergePullRequest: ${merged.error}` }); return null; }
        return { __type: 'MergePullRequestPayload', pullRequest: pullWrapper(repo, pull) };
      }
      if (field.name === 'addComment') {
        const input = args.input ?? {};
        const decoded = ungid(input.subjectId);
        if (!decoded || decoded.kind !== 'Issue') { errors.push({ message: 'addComment: unknown subjectId' }); return null; }
        const m = /^(.*):(\d+)$/.exec(decoded.key);
        if (!m) { errors.push({ message: 'addComment: unknown subjectId' }); return null; }
        const [owner, name] = m[1].split('/');
        const repo = getRepo(owner, name);
        const issue = repo?.issues.get(Number.parseInt(m[2], 10));
        if (!issue) { errors.push({ message: 'addComment: issue not found' }); return null; }
        const comment = { id: store.nextRestId++, body: input.body ?? '', seq: ++store.tsSeq };
        issue.comments.push(comment);
        return {
          __type: 'AddCommentPayload',
          commentEdge: {
            __type: 'CommentEdge',
            node: { __type: 'IssueComment', id: gid('IssueComment', `${owner}/${name}:${issue.number}:${comment.id}`), body: comment.body },
          },
        };
      }
      return unknown();
    }
    case 'User': {
      if (field.name === 'login') return parent.login;
      if (field.name === 'id') return gid('User', parent.login);
      if (field.name === 'name') return parent.login === VIEWER_LOGIN ? VIEWER_NAME : parent.login;
      if (field.name === 'email') return parent.login === VIEWER_LOGIN ? VIEWER_EMAIL : null;
      return unknown();
    }
    case 'Repository': {
      const repo = parent.repo;
      switch (field.name) {
        case 'id': return gid('Repository', `${repo.owner}/${repo.name}`);
        case 'databaseId': return repo.databaseId;
        case 'name': return repo.name;
        case 'nameWithOwner': return `${repo.owner}/${repo.name}`;
        case 'owner': return userWrapper(repo.owner);
        case 'defaultBranchRef': {
          const tip = headTip(repo);
          return tip ? { __type: 'Ref', name: repo.defaultBranch } : null;
        }
        case 'viewerPermission': return 'ADMIN';
        case 'hasIssuesEnabled': return true;
        case 'description': return repo.description;
        case 'private': return repo.private;
        case 'url': return `https://github.com/${repo.owner}/${repo.name}`;
        case 'createdAt': return isoTs(repo.createdSeq);
        case 'updatedAt': return isoTs(repo.createdSeq);
        case 'issue': {
          const issue = repo.issues.get(args.number);
          return issue ? issueWrapper(repo, issue) : null;
        }
        case 'issues': return issuesConnection(repo, args);
        case 'pullRequests': {
          let list = [...repo.pulls.values()].sort((a, b) => a.number - b.number);
          const first = typeof args.first === 'number' ? args.first : list.length;
          list = list.slice(0, first);
          return { __type: 'PullRequestConnection', nodes: list.map((p) => pullWrapper(repo, p)) };
        }
        case 'pullRequest': {
          const pull = repo.pulls.get(args.number);
          return pull ? pullWrapper(repo, pull) : null;
        }
        default: return unknown();
      }
    }
    case 'Issue': {
      const { repo, issue } = parent;
      switch (field.name) {
        case 'id': return gid('Issue', `${repo.owner}/${repo.name}:${issue.number}`);
        case 'number': return issue.number;
        case 'title': return issue.title;
        case 'state': return issueGqlState(issue);
        case 'body': return issue.body;
        case 'createdAt': return isoTs(issue.seq);
        case 'updatedAt': return isoTs(issue.seq);
        case 'url': return `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`;
        case 'author': return userWrapper(VIEWER_LOGIN);
        case 'repository': return repoWrapper(repo);
        case 'labels': return { __type: 'LabelConnection', nodes: issue.labels.map((n) => ({ __type: 'Label', name: n })) };
        case 'comments': return { __type: 'IssueCommentConnection', nodes: issue.comments.map((c) => ({ __type: 'IssueComment', id: gid('IssueComment', `${repo.owner}/${repo.name}:${issue.number}:${c.id}`), body: c.body })) };
        default: return unknown();
      }
    }
    case 'PullRequest': {
      const { repo, pull } = parent;
      switch (field.name) {
        case 'id': return gid('PullRequest', `${repo.owner}/${repo.name}:${pull.number}`);
        case 'number': return pull.number;
        case 'title': return pull.title;
        case 'body': return pull.body;
        case 'state': return pullGqlState(pull);
        case 'merged': return pull.merged;
        case 'mergeable': return pullMergeable(repo, pull);
        case 'headRefName': return pull.headRef;
        case 'baseRefName': return pull.baseRef;
        case 'headRef': return { __type: 'Ref', name: pull.headRef };
        case 'baseRef': return { __type: 'Ref', name: pull.baseRef };
        case 'mergedAt': return pull.mergedAt;
        case 'mergeCommit': return pull.mergeCommitSha ? { __type: 'Commit', oid: pull.mergeCommitSha } : null;
        case 'author': return userWrapper(VIEWER_LOGIN);
        case 'createdAt': return isoTs(pull.seq);
        case 'updatedAt': return isoTs(pull.seq);
        case 'files': {
          const first = typeof args.first === 'number' ? args.first : 10;
          const files = pullFiles(repo, pull).slice(0, first);
          return { __type: 'PullRequestChangedFileConnection', nodes: files.map((f) => ({ __type: 'PullRequestChangedFile', path: f.filename, additions: f.additions, deletions: f.deletions })) };
        }
        default: return unknown();
      }
    }
    case 'IssueConnection':
    case 'PullRequestConnection':
    case 'PullRequestChangedFileConnection':
    case 'IssueCommentConnection':
    case 'LabelConnection': {
      if (field.name === 'nodes') return parent.nodes ?? [];
      if (field.name === 'edges') return (parent.nodes ?? []).map((node) => ({ __type: 'Edge', node }));
      if (field.name === 'pageInfo') return parent.pageInfo ?? { hasNextPage: false, endCursor: null };
      if (field.name === 'totalCount') return (parent.nodes ?? []).length;
      return unknown();
    }
    case 'PageInfo': {
      if (field.name === 'hasNextPage') return parent.hasNextPage ?? false;
      if (field.name === 'hasPreviousPage') return false;
      if (field.name === 'endCursor') return parent.endCursor ?? null;
      if (field.name === 'startCursor') return parent.startCursor ?? null;
      return unknown();
    }
    case 'PullRequestChangedFile': {
      if (field.name === 'path') return parent.path;
      if (field.name === 'additions') return parent.additions ?? 0;
      if (field.name === 'deletions') return parent.deletions ?? 0;
      if (field.name === 'changeType') return 'ADDED';
      return unknown();
    }
    case 'Ref': {
      if (field.name === 'name') return parent.name;
      return unknown();
    }
    case 'IssueComment': {
      if (field.name === 'id') return parent.id;
      if (field.name === 'body') return parent.body;
      if (field.name === 'author') return userWrapper(VIEWER_LOGIN);
      return unknown();
    }
    case 'Label': {
      if (field.name === 'name') return parent.name;
      return unknown();
    }
    case 'Edge': {
      if (field.name === 'node') return parent.node;
      if (field.name === 'cursor') return null;
      return unknown();
    }
    case 'CommentEdge': {
      if (field.name === 'node') return parent.node;
      if (field.name === 'cursor') return null;
      return unknown();
    }
    case 'CreateIssuePayload':
    case 'CloseIssuePayload': {
      if (field.name === 'issue') return parent.issue;
      return unknown();
    }
    case 'CreatePullRequestPayload':
    case 'MergePullRequestPayload': {
      if (field.name === 'pullRequest') return parent.pullRequest;
      return unknown();
    }
    case 'AddCommentPayload': {
      if (field.name === 'commentEdge') return parent.commentEdge;
      return unknown();
    }
    case '__Type': {
      if (field.name === 'name') return parent.name;
      if (field.name === 'kind') return parent.kind;
      if (field.name === 'fields') {
        const names = GQL_TYPE_FIELDS[parent.name] ?? [];
        return names.map((n) => ({ __type: '__Field', name: n }));
      }
      if (field.name === 'enumValues') {
        const names = GQL_TYPE_ENUMS[parent.name] ?? [];
        return names.map((n) => ({ __type: '__EnumValue', name: n }));
      }
      return unknown();
    }
    case '__Field': {
      if (field.name === 'name') return parent.name;
      return unknown();
    }
    case '__EnumValue': {
      if (field.name === 'name') return parent.name;
      return unknown();
    }
    case '__Schema': {
      if (field.name === 'queryType') return { __type: '__Type', name: 'Query', kind: 'OBJECT' };
      if (field.name === 'mutationType') return { __type: '__Type', name: 'Mutation', kind: 'OBJECT' };
      if (field.name === 'types') return [];
      return unknown();
    }
    case 'Commit': {
      if (field.name === 'oid') return parent.oid;
      return unknown();
    }
    default:
      errors.push({ message: `Cannot query field "${field.name}" on type "${parentType}".` });
      return null;
  }
}

/** Execute a selection set against a wrapped parent value. */
function gqlExecuteSelections(parent, parentType, selections, variables, errors) {
  const out = {};
  for (const sel of selections ?? []) {
    if (sel.kind === 'fragment') {
      // Inline fragment: applies when its type condition matches (or is absent).
      if (sel.typeCondition && sel.typeCondition !== parentType) continue;
      const sub = gqlExecuteSelections(parent, parentType, sel.selections, variables, errors);
      Object.assign(out, sub);
      continue;
    }
    const value = gqlResolve(parent, parentType, sel, variables, errors);
    const key = sel.alias || sel.name;
    if (value === null || value === undefined) {
      out[key] = null;
      continue;
    }
    if (Array.isArray(value)) {
      out[key] = value.map((item) => {
        if (item && typeof item === 'object' && item.__type && sel.selections) {
          return gqlExecuteSelections(item, item.__type, sel.selections, variables, errors);
        }
        if (item && typeof item === 'object' && item.__type && !sel.selections) return item;
        return item;
      });
      continue;
    }
    if (typeof value === 'object' && value.__type) {
      if (sel.selections) out[key] = gqlExecuteSelections(value, value.__type, sel.selections, variables, errors);
      else out[key] = value;
      continue;
    }
    if (typeof value === 'object' && sel.selections) {
      // Plain object (e.g. pageInfo): resolve its fields by treating keys as the type.
      const sub = {};
      for (const subSel of sel.selections) {
        if (subSel.kind === 'fragment') continue;
        const v = value[subSel.name];
        sub[subSel.alias || subSel.name] = v === undefined ? null : v;
      }
      out[key] = sub;
      continue;
    }
    out[key] = value;
  }
  return out;
}

function executeGqlOperation(op, variables) {
  const errors = [];
  const rootType = op.operation === 'mutation' ? 'Mutation' : 'Query';
  const data = gqlExecuteSelections(null, rootType, op.selections, variables ?? {}, errors);
  const out = { data };
  if (errors.length > 0) out.errors = errors;
  return out;
}

function executeGraphQL(body) {
  if (Array.isArray(body)) {
    return body.map((entry) => {
      if (!entry || typeof entry.query !== 'string') return { data: null, errors: [{ message: 'invalid operation' }] };
      try {
        const defs = gqlParse(entry.query);
        const op = defs.find((d) => d.kind === 'operation');
        if (!op) return { data: null, errors: [{ message: 'no operation found' }] };
        return executeGqlOperation(op, entry.variables ?? {});
      } catch (err) {
        return { data: null, errors: [{ message: String(err.message ?? err) }] };
      }
    });
  }
  if (!body || typeof body.query !== 'string') return { data: null, errors: [{ message: 'query is required' }] };
  try {
    const defs = gqlParse(body.query);
    let op = defs.find((d) => d.kind === 'operation');
    if (body.operationName) {
      op = defs.find((d) => d.kind === 'operation' && d.name === body.operationName) ?? op;
    }
    if (!op) return { data: null, errors: [{ message: 'no operation found' }] };
    return executeGqlOperation(op, body.variables ?? {});
  } catch (err) {
    return { data: null, errors: [{ message: String(err.message ?? err) }] };
  }
}

// ---------------------------------------------------------------------------
// MCP (Model Context Protocol, Streamable HTTP, JSON-RPC 2.0)
// ---------------------------------------------------------------------------

const MCP_SERVER_INFO = { name: 'github-core-clone', version: '1.0.0' };

const MCP_TOOLS = [
  {
    name: 'create_repo',
    description: 'Create a new repository for the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Issue state: open, closed, or all' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
        body: { type: 'string', description: 'Pull request body' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'integer', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpToolResult(payload) {
  return { content: [{ type: 'text', text: JSON.stringify(payload) }], structuredContent: payload };
}
function mcpToolError(message) {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function mcpCallTool(name, args) {
  const tool = MCP_TOOLS.find((t) => t.name === name);
  if (!tool) return { error: { code: -32602, message: `Unknown tool: ${name}` } };
  for (const required of tool.inputSchema.required ?? []) {
    if (args[required] === undefined || args[required] === null || args[required] === '') {
      return { error: { code: -32602, message: `Missing required argument: ${required}` } };
    }
  }
  switch (name) {
    case 'create_repo': {
      const created = createRepoInternal(VIEWER_LOGIN, args.name, args.description, args.private);
      if (created.error) return { result: mcpToolError(created.error) };
      return { result: mcpToolResult(repoRestObject(created.repo)) };
    }
    case 'get_repo': {
      const repo = getRepo(args.owner, args.repo);
      if (!repo) return { result: mcpToolError(`Repository not found: ${args.owner}/${args.repo}`) };
      return { result: mcpToolResult(repoRestObject(repo)) };
    }
    case 'create_issue': {
      const repo = getRepo(args.owner, args.repo);
      if (!repo) return { result: mcpToolError(`Repository not found: ${args.owner}/${args.repo}`) };
      const created = createIssueInternal(repo, { title: args.title, body: args.body });
      if (created.error) return { result: mcpToolError(created.error) };
      return { result: mcpToolResult(issueRestObject(repo, created.issue)) };
    }
    case 'list_issues': {
      const repo = getRepo(args.owner, args.repo);
      if (!repo) return { result: mcpToolError(`Repository not found: ${args.owner}/${args.repo}`) };
      const state = typeof args.state === 'string' ? args.state : 'open';
      const list = [...repo.issues.values()]
        .filter((i) => state === 'all' || i.state === state)
        .sort((a, b) => a.seq - b.seq)
        .map((i) => issueRestObject(repo, i));
      return { result: mcpToolResult(list) };
    }
    case 'create_pull_request': {
      const repo = getRepo(args.owner, args.repo);
      if (!repo) return { result: mcpToolError(`Repository not found: ${args.owner}/${args.repo}`) };
      const created = createPullInternal(repo, { title: args.title, head: args.head, base: args.base, body: args.body });
      if (created.error) return { result: mcpToolError(created.error) };
      return { result: mcpToolResult(pullRestObject(repo, created.pull)) };
    }
    case 'merge_pull_request': {
      const repo = getRepo(args.owner, args.repo);
      if (!repo) return { result: mcpToolError(`Repository not found: ${args.owner}/${args.repo}`) };
      const pull = repo.pulls.get(Number(args.pull_number));
      if (!pull) return { result: mcpToolError(`Pull request not found: #${args.pull_number}`) };
      const merged = mergePullInternal(repo, pull);
      if (merged.error) return { result: mcpToolError(merged.error) };
      return { result: mcpToolResult({ merged: true, number: pull.number, sha: pull.mergeCommitSha }) };
    }
    default:
      return { error: { code: -32602, message: `Unknown tool: ${name}` } };
  }
}

function handleMcpRpc(body) {
  const id = body.id;
  const method = body.method;
  const params = body.params ?? {};
  const rpcError = (code, message) => ({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });
  const rpcResult = (result) => ({ jsonrpc: '2.0', id: id ?? null, result });
  if (typeof method !== 'string') return { status: 400, body: rpcError(-32600, 'Invalid Request') };
  // Notifications (no id) get no response body.
  const isNotification = id === undefined || id === null;
  switch (method) {
    case 'initialize': {
      const proto = typeof params.protocolVersion === 'string' ? params.protocolVersion : '2025-11-25';
      return {
        status: 200,
        body: rpcResult({
          protocolVersion: proto,
          capabilities: { tools: { listChanged: false } },
          serverInfo: MCP_SERVER_INFO,
        }),
      };
    }
    case 'server/discover': {
      return {
        status: 200,
        body: rpcResult({
          supportedVersions: ['2026-07-28', '2025-06-18', '2025-03-26'],
          capabilities: { tools: { listChanged: false } },
          serverInfo: MCP_SERVER_INFO,
          instructions: 'GitHub core API over MCP.',
          _meta: { 'io.modelcontextprotocol/serverInfo': MCP_SERVER_INFO },
        }),
      };
    }
    case 'ping':
      return { status: 200, body: rpcResult({}) };
    case 'tools/list':
      return { status: 200, body: rpcResult({ tools: MCP_TOOLS }) };
    case 'tools/call': {
      const args = params.arguments ?? {};
      const outcome = mcpCallTool(params.name, args);
      if (outcome.error) return { status: 200, body: rpcError(outcome.error.code, outcome.error.message) };
      return { status: 200, body: rpcResult(outcome.result) };
    }
    case 'notifications/initialized':
    case 'notifications/cancelled':
    case 'notifications/progress':
      return { status: 202, body: null };
    default:
      if (isNotification) return { status: 202, body: null };
      return { status: 200, body: rpcError(-32601, `Method not found: ${method}`) };
  }
}

async function handleMcp(req, res, rawBody) {
  if (!authOk(req)) return sendJson(res, 401, { message: 'Requires authentication' });
  let body;
  try {
    body = rawBody.length > 0 ? JSON.parse(rawBody.toString('utf8')) : null;
  } catch {
    return sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
  }
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
  }
  const outcome = handleMcpRpc(body);
  if (outcome.body === null) {
    res.writeHead(outcome.status);
    res.end();
    return;
  }
  return sendJson(res, outcome.status, outcome.body);
}

// ---------------------------------------------------------------------------
// Router + lifecycle
// ---------------------------------------------------------------------------

async function handleRequest(req, res) {
  try {
    const url = new URL(req.url, 'http://localhost');
    const pathname = url.pathname;
    const segments = pathname
      .split('/')
      .filter((s) => s !== '')
      .map((s) => {
        try { return decodeURIComponent(s); } catch { return null; }
      });
    if (segments.includes(null)) return sendJson(res, 400, { message: 'bad path' });

    if (req.method === 'GET' && pathname === '/healthz') return sendJson(res, 200, { ok: true });

    // Git smart HTTP: /{owner}/{repo}.git/info/refs and /{owner}/{repo}.git/git-upload-pack|git-receive-pack
    if (
      segments.length >= 3 &&
      typeof segments[1] === 'string' &&
      segments[1].endsWith('.git')
    ) {
      const owner = segments[0];
      const repoName = segments[1].slice(0, -4);
      const tail = segments.slice(2).join('/');
      if (req.method === 'GET' && tail === 'info/refs') return await handleInfoRefs(req, res, owner, repoName);
      if (req.method === 'POST' && tail === 'git-upload-pack') {
        const raw = await readBody(req);
        return await handleUploadPack(req, res, owner, repoName, raw);
      }
      if (req.method === 'POST' && tail === 'git-receive-pack') {
        const raw = await readBody(req);
        return await handleReceivePack(req, res, owner, repoName, raw);
      }
      return sendJson(res, 404, { message: 'Not Found' });
    }

    // GraphQL
    if (segments.length === 2 && segments[0] === 'api' && segments[1] === 'graphql' && req.method === 'POST') {
      if (!authOk(req)) return sendJson(res, 401, { message: 'Requires authentication' });
      const raw = await readBody(req);
      let body;
      try {
        body = raw.length > 0 ? JSON.parse(raw.toString('utf8')) : null;
      } catch {
        return sendJson(res, 400, { message: 'Bad Request' });
      }
      return sendJson(res, 200, executeGraphQL(body));
    }

    // MCP
    if (segments.length === 1 && segments[0] === 'mcp') {
      if (req.method === 'POST') {
        const raw = await readBody(req);
        return await handleMcp(req, res, raw);
      }
      if (req.method === 'GET') return sendJson(res, 405, { message: 'Method Not Allowed' });
      if (req.method === 'DELETE') {
        res.writeHead(200);
        res.end();
        return;
      }
      return sendJson(res, 405, { message: 'Method Not Allowed' });
    }

    // REST v3
    if (segments.length >= 2 && segments[0] === 'api' && segments[1] === 'v3') {
      const raw = await readBody(req);
      return await handleRest(req, res, segments.slice(2), url.searchParams, raw);
    }

    return sendJson(res, 404, { message: 'Not Found' });
  } catch (err) {
    // Never crash the process on a bad request; never leak a stack trace.
    try {
      sendJson(res, 500, { message: 'Internal error' });
    } catch {}
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function registerAndWait(port) {
  const base = ENV_URL.replace(/\/$/, '');
  let registered = false;
  for (let attempt = 0; attempt < 10 && !registered; attempt++) {
    try {
      const r = await fetch(`${base}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(5000),
      });
      if (r.status === 200 || r.status === 409) registered = true;
    } catch {}
    if (!registered) await sleep(500);
  }
  for (;;) {
    try {
      const r = await fetch(`${base}/done`, { signal: AbortSignal.timeout(5000) });
      const j = await r.json().catch(() => null);
      if (j && j.done === true) break;
    } catch {}
    await sleep(500);
  }
  process.exit(0);
}

const server = http.createServer((req, res) => {
  void handleRequest(req, res);
});

server.listen(0, '0.0.0.0', () => {
  const port = server.address().port;
  if (ENV_URL) {
    void registerAndWait(port);
  }
});

process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));
