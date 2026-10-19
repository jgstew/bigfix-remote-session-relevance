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

**On a BigFix root server, no setup is needed.** Run as root (Linux) or
Administrator (Windows) and the server's own REST API credentials are used
automatically, as an extra `rest` connection named `local-root-server`, the
same way besapi logs in first with them. Linux reads
`/var/opt/BESServer/Applications/MasterOperatorCredentials` and decrypts the
password with the `CryptoUtility` next to it; Windows reads
`HKLM\SOFTWARE\Wow6432Node\BigFix\Enterprise Server\MFSConfig` and decrypts
it with DPAPI. Nothing is written to the config file, and the password never
appears in output or logs (`--show-config` says `local root server`). As a
normal user on a root server, or when the password cannot be decrypted, the
connection is left out when anything else is configured. To turn it off, set `BFRSR_LOCAL_ROOT_SERVER=0` or
`local_root_server = false` under `[defaults]`.

## CLI

```bash
bigfix-remote-session-relevance "names of bes sites"            # one answer per line
bigfix-remote-session-relevance --json "ids of bes computers"   # list of result objects
bigfix-remote-session-relevance --all "now"                     # every connection, not one per deployment (= -all, --all-connections)
bigfix-remote-session-relevance --backend webreports --raw "1"  # raw server response
bigfix-remote-session-relevance --keep-escapes '"a%09b"'        # a%09b: % and control characters as %xx
bigfix-remote-session-relevance --keys "id name" \
    "(id of it, name of it) of bes computers"                  # Explorer extras
echo "number of bes fixlets" | bigfix-remote-session-relevance -
bigfix-remote-session-relevance --show-config                   # connections, no secrets
bigfix-remote-session-relevance --show-certs | --trust-cert NAME | --forget-cert HOST:PORT
```

Answers go to stdout; errors and `-v` metadata go to stderr.

Answer text comes from the server, so plain-text output to a **terminal**
shows control characters as `%xx`: ESC, CR, LF, the other C0 controls except
tab, DEL and the C1 controls (0x80–0x9F). An answer can't recolour or clear
your terminal, and an answer containing a newline stays on one line
(`x%0ay`). `%` itself is left as is, so `%SystemRoot%` stays readable; use
`--keep-escapes` for the unambiguous form, where `%` is `%25`. Error messages
on a terminal keep their line breaks but lose the other control characters.

Output to a **pipe or file** is the answer text as is, one answer per line,
so an answer containing a newline prints as several lines. Use `--json` when
the answer boundaries matter, or `--keep-escapes`. `--json` and `--raw` are
never changed, terminal or not. A pipe into something that writes to the
terminal (`| less -R`, `| tee /dev/tty`) is not escaped either.

Text the output encoding can't hold, such as a lone surrogate (`\ud800` in
a JSON answer), is written as `\ud800` instead of stopping the run.

Results stream in as each deployment answers (completion order), so a slow
or unreachable server no longer holds up the ones that already finished.
Plain text and `--raw` stream; `--json` is one document, so it prints once
everything is in. Exit codes are always decided after the full fan-out.

When several results come back, plain text ends with a summary that
collapses identical answers, most common first:

```
== summary: 3 results, 2 distinct answers
2× 1234
    prod-root (rest), dr-root (rest)
1× 87
    lab-wr (webreports)
```

Results are grouped by answers, answer type and error (not timing, backend
or server), and identical errors collapse too. The summary only appears when
it actually collapses something.

| Exit code | Meaning |
|---|---|
| 0 | every queried deployment answered |
| 1 | a session relevance error |
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

    async for result in client.evaluate_stream("number of bes computers"):
        print(result.connection, result.answers)  # as each deployment answers
    keyed = await client.evaluate_explorer(
        "(id of it, name of it) of bes computers", keys="id name"
    )
```

String answers are the decoded text on every backend (`"a%09b"` gives
`a<TAB>b`). Pass `unescape=False` to any `evaluate*` method or to
`evaluate_session_relevance()` / `async_evaluate_session_relevance()` (CLI:
`--keep-escapes`) to get `%` and control characters as `%xx` instead
(`a%09b`), the form Web Reports and qna print, again the same on every
backend. `escape_answer()` / `unescape_answer()` convert between the two;
`escape_result()` does it for a whole result from a backend used directly.

`SessionRelevanceClient` has the same methods, synchronously, and works even
inside a running event loop. Single backends (`RestBackend`,
`ExplorerBackend`, `WebReportsBackend`) can be used directly too.

The query is always named `session_relevance` (never a bare `relevance`, which
could mean client relevance): `result.session_relevance`, the `to_dict()` /
`--json` key, the error kind, and the `session_relevance=` /
`session_relevances=` parameters.

> **Upgrading from 0.4 or earlier:** 0.5.0 renamed, with no alias,
> `result.relevance` → `result.session_relevance` (and the `--json` key),
> the `relevance=` / `relevances=` parameters → `session_relevance=` /
> `session_relevances=`, error kind `"relevance"` → `"session_relevance"`, and
> `RelevanceError` → `SessionRelevanceEvaluationError`. Helpers follow suit
> (`encode_session_relevance`, `parse_session_relevance_response`, …).

## Compatibility

From 1.0.0, releases follow [semantic versioning](https://semver.org/).
Removing or changing any of these needs a new major version:

- **Library:** the names in `bigfix_remote_session_relevance.__all__` and
  their documented parameters, keyword names included.
- **Results:** the `SessionRelevanceResult` and `ResultError` fields, the
  `to_dict()` keys and value types, the error kinds (`ERROR_KINDS`) and the
  exception class `raise_for_error()` raises for each.
- **CLI:** flags, exit codes, and the `--json` output (`to_dict()` per result).
- **Config file:** the keys it accepts and what they mean.

Additions (a new result field or `to_dict()` key, error kind or code, flag
or config key) come in minor releases, so code that switches on error kinds
or codes should allow ones it doesn't know.

Not covered: the plain-text CLI layout and summary, stderr and log messages,
error message wording, `detail` and `raw` (the server's own text), and
anything not in `__all__`.

## Development

```bash
uv sync
uv run pytest                                  # offline; live tests skip
BFRSR_LIVE_TESTS=1 uv run pytest tests/integration -n0   # against your config
uv run python scripts/capture_fixtures.py      # refresh redacted fixtures
```

See [DESIGN.md](DESIGN.md) for the specification and [AGENTS.md](AGENTS.md)
for contributor notes.
