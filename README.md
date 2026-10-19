# dockerhub

A cross-platform Docker Hub token-management CLI.

Authenticates to Docker Hub with the same OAuth device-code flow as
`docker login`, persists the session, and lets you list, create,
inspect, and delete Docker Hub personal access tokens (PATs) from the
terminal.

```
$ dockerhub login
User code: HWVB-LSNH
Verify URL: https://login.docker.com/activate?user_code=HWVB-LSNH
(opens browser)
Logged in as yourname.

$ dockerhub token list
LABEL                  UUID                                  SCOPES       STATUS   CREATED               LAST USED             EXPIRES
gh repo turtlebot3     d8495a37-4a21-44ca-b55d-377ce407f29d  repo:write   active   2026-10-14T09:40:09Z  2026-10-14T15:04:22Z  never
turtlebot-lab          c4ea632d-6054-4ccc-86ad-cb28478ab4c7  repo:write   active   2026-10-12T20:32:19Z  2026-10-14T14:30:01Z  never
polymarket             81df2fb2-38e3-4870-afe6-1230b3a999fb  repo:write   active   2026-02-22T14:12:18Z  2026-10-09T16:22:38Z  never
...
```

## Why

`docker login` can mint a token, but it cannot manage tokens. The only
tool that ever did ([`hub-tool`](https://github.com/docker/hub-tool))
was archived in May 2026. Docker Hub's web UI is the only current way
to list, create, and scope PATs. This CLI fills that gap.

## Install

```sh
bun add -g dockerhub-cli        # Bun
# or
npm install -g dockerhub-cli    # Node 20+
```

The binary installs as `dockerhub`.

## Commands

```
dockerhub login                  # device-code OAuth + browser auth
dockerhub logout                 # revoke session, erase local credentials
dockerhub token list             # table (or --json)
dockerhub token inspect <uuid>   # single token details
dockerhub token create --label <name> [--scopes <csv>] [--expires <date>]
dockerhub token delete <uuid> [--force]
dockerhub whoami                 # print logged-in username
dockerhub --version
```

## How it works

OAuth 2.0 device-code flow against Docker's Auth0 tenant
(`login.docker.com`), using Docker's public client. The CLI never sees
your password or 2FA code — both stay in the browser.

The CLI persists the long-lived OAuth refresh token at
`$XDG_CONFIG_HOME/dockerhub/auth.json` (mode 0600 on POSIX). The
short-lived access token is held in memory only and refreshed silently
on every command. Refresh-token rotation is handled atomically under
a file lock to prevent concurrent-CLI races from triggering reuse
detection and forcing a full re-login.

Full architecture decisions live in [`docs/adr/`](docs/adr/). Phase 0
probe results (which proved the Hub accepts the device-flow token for
token management) are in
[`docs/adr/0001-phase-0-result.md`](docs/adr/0001-phase-0-result.md).

## Risks (read this)

1. **Borrowed OAuth client ID.** This CLI uses Docker's public
   client ID for `docker login`. Docker can rotate or revoke it
   without notice. See
   [`docs/adr/0007-borrowed-oauth-client-id.md`](docs/adr/0007-borrowed-oauth-client-id.md).
2. **No encryption at rest.** The auth file is 0600 plaintext,
   matching `aws`, `npm`, and `docker login`. It does not protect
   against malware running as your user. See
   [`docs/adr/0002-credential-storage.md`](docs/adr/0002-credential-storage.md).
3. **Refresh-token reuse is fatal.** A bug that replays a used
   refresh token would revoke the entire token family and force
   re-login. The CLI guards against this with a single-flight
   `flock` lockfile. See
   [`docs/adr/0003-refresh-token-concurrency.md`](docs/adr/0003-refresh-token-concurrency.md).
4. **Hub fair-use throttling.** Excessive token creation may rate-
   limit. There is no retry-and-backoff in the CLI today.

## Development

```sh
bun install
bun run dev -- token list --json    # run from source
bun test                            # mock HTTP server + unit tests
bun run build                       # produce dist/ for npm publish
```

Project layout:

```
src/
  types.ts          single source of truth for all data shapes
  errors.ts         CLIError + ExitCode mapping
  constants.ts      tenant/hub URLs, client ID
  jwt.ts            base64url decoder + id_token parser
  store.ts          atomic file I/O + single-flight flock
  auth.ts           OAuth device-flow, refresh, revoke
  hub.ts            Hub API client (list, create, inspect, delete)
  output.ts         table + --json formatting
  paths.ts          XDG-aware data directory resolver
  cli.ts            cac subcommand wiring + entry point
tests/
  mocks/            fake login.docker.com + hub.docker.com servers
  *.test.ts         unit + integration tests against the mocks
docs/
  adr/              architecture decision records
  glossary.md
```

## License

MIT.