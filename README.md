# bigfix-remote-session-relevance

Evaluate BigFix **session relevance** through the root server REST API,
BigFix Explorer, the Web Reports SOAP API, or BigFix SaaS, against every configured
deployment at once, and get the same result back whichever one answered.

```bash
uvx bigfix-remote-session-relevance "number of bes computers"
```

The session-relevance counterpart to
[bigfix-remote-client-relevance](https://github.com/jgstew/bigfix-remote-client-relevance).

## What it does

- **One result type.** REST (JSON), Explorer (JSON) and Web Reports (SOAP
  XML) all return a `SessionRelevanceResult` with native answers (`int`,
  `bool`, `str`, tuples), the type string, plurality and evaluation time.
  Callers never see the wire format; `result.raw` has it when asked for.
- **Consistent errors.** Relevance errors, bad credentials, unreachable hosts
  and login pages come back as results with `error.kind` set. The kind and
  message are the same on every backend.
- **Many servers.** Any number of root servers, Explorers and Web Reports
  servers. Connections to the same deployment are recognized automatically
  (`sha256 of gather url of bes license`), and by default each deployment is
  queried once, concurrently, with failover between its connections.
- **Trust on first use** for self-signed BigFix certificates: confirm a
  certificate once and it is pinned. A changed certificate is a hard error.
- **Auth:** Basic or bearer token (11.0.6+ "API key") for REST and Explorer,
  mTLS client certificates for Explorer, username/password for Web Reports.
  BigFix SaaS signs in with email/password (TOTP prompted when required).
- **Explorer extras** (`keys`, `filters`) are additive and opt in.
- **Async first**, with an equally capable sync API. Pure-Python
  dependencies only.

## Setup

```bash
uvx bigfix-remote-session-relevance --setup
```

The wizard asks for a host, username and password, probes the REST API
(52311), Explorer (9383) and Web Reports (443/8083/80/8080), pins
certificates after showing their fingerprints, and writes
`~/.bigfix/.remote_session_connections.toml` (mode 0600).

For BigFix SaaS, enter `login.bigfix.com` (or `eulogin.bigfix.com`) as the
host, then your email and password; a TOTP code is asked for only if your
account uses MFA. Setup signs in once and saves one connection per BigFix
server your account can reach. A rejected sign-in is never retried or saved:
BigFix SaaS locks an account after 100 failed logins. See
[remote_session_connections.example.toml](remote_session_connections.example.toml)
for every option. `server` is normally just a host name: `https://` and the
backend's default port are assumed.

Passwords can live in the file, or better, in environment variables named by
`password_env`.

## CLI

```bash
bigfix-remote-session-relevance "names of bes sites"            # one answer per line
bigfix-remote-session-relevance --json "ids of bes computers"   # list of result objects
bigfix-remote-session-relevance --all-connections "now"         # every connection, not one per deployment
bigfix-remote-session-relevance --backend webreports --raw "1"  # raw server response
bigfix-remote-session-relevance --keys "id name" \
    "(id of it, name of it) of bes computers"                  # Explorer extras
echo "number of bes fixlets" | bigfix-remote-session-relevance -
bigfix-remote-session-relevance --show-config                   # connections, no secrets
bigfix-remote-session-relevance --show-certs | --trust-cert NAME | --forget-cert HOST:PORT
```

Answers go to stdout; errors and `-v` metadata go to stderr.

| Exit code | Meaning |
|---|---|
| 0 | every queried deployment answered |
| 1 | a relevance error |
| 2 | nothing reachable, or credentials rejected everywhere |
| 3 | partial: some deployments failed |
| 64 | usage or configuration error |

## Library

```python
from bigfix_remote_session_relevance import evaluate_session_relevance

for result in evaluate_session_relevance("(id of it, name of it) of bes computers"):
    if result.ok:
        print(result.connection, result.answers)  # ((1, 'host-a'), ...)
    else:
        print(result.connection, result.error.kind, result.error.message)
```

```python
from bigfix_remote_session_relevance import AsyncSessionRelevanceClient

async with AsyncSessionRelevanceClient() as client:  # default config
    results = await client.evaluate("number of bes computers")
    results.raise_for_error()  # opt into exceptions
    keyed = await client.evaluate_explorer(
        "(id of it, name of it) of bes computers", keys="id name"
    )
```

`SessionRelevanceClient` has the same methods, synchronously, and works even
inside a running event loop. Single backends (`RestBackend`,
`ExplorerBackend`, `WebReportsBackend`) can be used directly too.

## Development

```bash
uv sync
uv run pytest                                  # offline; live tests skip
BFRSR_LIVE_TESTS=1 uv run pytest tests/integration -n0   # against your config
uv run python scripts/capture_fixtures.py      # refresh redacted fixtures
```

See [DESIGN.md](DESIGN.md) for the specification and [AGENTS.md](AGENTS.md)
for contributor notes.
