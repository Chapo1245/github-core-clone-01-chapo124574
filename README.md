# github-core-clone

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/Chapo1245/github-core-clone-01-chapo124574/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/Chapo1245/github-core-clone-01-chapo124574/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A fast, in-memory GitHub core clone in a single Node.js process (stdlib only,
no dependencies): git smart HTTP (protocol v2 + v0), REST v3, GraphQL v4 and
MCP (Model Context Protocol, Streamable HTTP) over one shared in-memory store.

## Run

```sh
node main.ts
```

The server listens on an ephemeral port (`listen(0)`). When
`MAKEFUN_ENV_URL` is set it registers its port with the environment and exits
when the environment reports `done`. `MAKEFUN_SHOP_TOKEN` sets the bearer
token accepted for authenticated endpoints; when unset, any non-empty token
is accepted.

## What it implements

- **Git smart HTTP**: `GET /{owner}/{repo}.git/info/refs` (protocol v2
  advertisement, `ls-refs` and `fetch` v2, v0 `upload-pack` with sideband,
  `receive-pack` with per-ref `ok`/`ng` reporting, non-fast-forward refusal,
  shallow fetch, annotated tags, pack reading/writing with delta resolution).
- **REST v3** (`/api/v3/`): repos, branches, refs, commits, contents, labels,
  issues, pull requests (incl. squash merge), pagination via `Link` headers.
- **GraphQL** (`/api/graphql`): viewer, repository, node, introspection,
  issue/pull-request connections with cursor pagination, and the
  `createIssue` / `closeIssue` / `createPullRequest` / `mergePullRequest` /
  `addComment` mutations. Global ids are opaque base64 values.
- **MCP** (`/mcp`): `initialize`, `server/discover`, `tools/list`,
  `tools/call` for `create_repo`, `get_repo`, `create_issue`,
  `list_issues`, `create_pull_request`, `merge_pull_request`.

## Design notes

- Everything is in-memory (`Map`s); no wall clock or randomness in state, so
  replaying the same request sequence yields the same state.
- Git objects are real SHA-1 objects (blob/tree/commit/tag) with zlib pack
  encoding; packs are written without deltas (the protocol does not require
  them).
- Timestamps are deterministic (an epoch counter), never `Date.now()` in
  state.
- Single file, stdlib only (`node:http`, `node:crypto`, `node:zlib`).

## License

MIT

<sub>Entered on [make.fun](https://make.fun/?ref=wtacm6ft&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
