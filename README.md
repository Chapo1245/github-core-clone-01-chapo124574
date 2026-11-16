[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/Chapo1245/github-core-clone-01-chapo124574/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/Chapo1245/github-core-clone-01-chapo124574/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

# Iron Forge — a standalone GitHub-compatible git forge

A single Node 22 process serving git smart HTTP (protocol v2 upload-pack /
v0 receive-pack), the REST v3 API, GraphQL v4 and MCP from its own in-memory
store. Standard library only: no dependencies, no git binary, no outside
service, no UI.

## Run

```sh
node main.ts
```

The server binds an ephemeral port. With `MAKEFUN_ENV_URL` set (a make.fun
trial) it registers the port with the suite and long-polls `/done`, exiting 0
when the suite finishes. Without it, it serves until killed.

`FORGE_TRANSPORT=tcp` (default) uses a hand-rolled HTTP/1.1 server over
`node:net` for the lowest per-request overhead; `FORGE_TRANSPORT=http` uses
`node:http` instead. `MAKEFUN_SHOP_TOKEN` sets the bearer token the API
requires; when unset, any non-empty bearer token is accepted (local runs).

## What it serves

- **Git smart HTTP** at `/{owner}/{repo}.git`: v2 capability advertisement,
  `ls-refs` (peel / symrefs / unborn / ref-prefix), v2 and v0 fetch with
  thin-pack, shallow/deepen, have/want negotiation and sideband packfiles,
  and v0 receive-pack with fast-forward enforcement and per-ref
  report-status. Packs are plain (no deltas); fetch responses are cached
  per repository generation.
- **REST v3** under `/api/v3`: repositories, branches, commits, contents
  (create / update with stale-sha 409 / delete), labels, issues, comments,
  pull requests and squash merge with conflict detection.
- **GraphQL** at `/api/graphql`: repository / issue / pull-request queries,
  introspection, cursor pagination, and the create/close-issue,
  create/merge-pull-request and add-comment mutations, with opaque stable
  global ids.
- **MCP** at `/mcp`: Streamable HTTP, revision 2026-07-28 via
  `server/discover` (legacy `initialize` handshake also answered), six
  tools (`create_repo`, `get_repo`, `create_issue`, `list_issues`,
  `create_pull_request`, `merge_pull_request`) acting on the same store
  as REST.

## Performance

Hot paths are built for the four timed workloads: pre-serialized issue
responses, per-generation cached advertisements / ls-refs / fetch packs,
single-call zlib inflate per pack object, and minimal per-request
allocation in the transport. See the repository history for measured
local numbers.

## License

MIT. See `LICENSE`.

<sub>Entered on [make.fun](https://make.fun/?ref=wtacm6ft&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
