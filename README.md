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
  certificate once (now, or later for GUIs) and it is pinned. A changed
  certificate is a hard error, and no credentials reach it.
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
`~/.bigfix/.remote_session_connections.toml` (mode 0600). A host entered
with a port (`bes-root.local:52311`) is probed only on that port: every
backend over https, plus Web Reports over http. One entered as `https://`
is probed only over https (Web Reports still on 443 and 8083), and
`http://` probes only Web Reports.

When the REST API answers, setup also asks the root server for the Explorer
and Web Reports servers registered with it (`/api/explorers`,
`/api/webreports`), so ones on other machines can be found. It shows the
ones it has not already tried and asks before sending your username and
password to them (default no). Those reached over `http://` are marked
cleartext. If you agree, they are probed with the same certificate prompts,
marked "listed by the root server", and offered for saving like the rest.
The root server answers these lists only for a master operator. For anyone
else, setup says so on the REST line and carries on. The lists name a
server as the root server knows it, which can be a short machine name that
does not resolve from where you run setup (it then shows as unreachable),
or the root server's own Explorer under a second name. Setup that probes
only Explorer or Web Reports (`run_setup(backends=...)` without `rest`)
never reads the lists.

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
| 1 | a session relevance error; `--trust-cert` declined, `--forget-cert` found no pin |
| 2 | nothing reachable, or credentials rejected everywhere; `--discover-deployments` found no id |
| 3 | partial: some deployments failed |
| 64 | usage or configuration error, or no connection matched `--connection` / `--backend` |

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

`integer` and `boolean` answers are `int` and `bool`; every other type
(`floating point`, `date`, `version`, `time interval`, …) is text, the same
on REST, Explorer and Web Reports (a `time` from Web Reports is converted
from ISO 8601 to the BigFix form the others send). BigFix SaaS is the one
exception for numbers: its gateway re-encodes them as JavaScript numbers, so
a floating point can read `3` instead of `3.0` and integers above 2**53 lose
precision (ask for `as string` when the exact value matters).

String answers are the decoded text on every backend (`"a%09b"` gives
`a<TAB>b`). Pass `unescape=False` to any `evaluate*` method or to
`evaluate_session_relevance()` / `async_evaluate_session_relevance()` (CLI:
`--keep-escapes`) to get `%` and control characters as `%xx` instead
(`a%09b`), the form Web Reports and qna print, again the same on every
backend. `escape_answer()` / `unescape_answer()` convert between the two;
`escape_result()` does it for a whole result from a backend used directly.

`SessionRelevanceClient` has the same methods, synchronously, and works even
inside a running event loop. Single backends (`RestBackend`,
`ExplorerBackend`, `WebReportsBackend`, `SaasBackend`) can be used directly
too.

The query is always named `session_relevance` (never a bare `relevance`, which
could mean client relevance): `result.session_relevance`, the `to_dict()` /
`--json` key, the error kind, and the `session_relevance=` /
`session_relevances=` parameters.

### Trust on first use

BigFix servers usually present self-signed certificates. With the default
`verify = "tofu"`, a certificate no CA vouches for is decided by the
`TrustStore` passed as `trust=`, and a pinned one is from then on the *only*
certificate that host:port may present. Either way the decision happens in
the TLS handshake, before any request: an unpinned certificate that is
refused, or a pinned host presenting a different one (`tls` /
`pin_mismatch`), receives nothing after the handshake: no request, no
`Authorization` header, no Web Reports password. `tests/unit/test_trust.py` proves this against a
local TLS server that records every byte.

Choose how a first-use certificate is decided:

```python
from bigfix_remote_session_relevance import AsyncSessionRelevanceClient, TrustStore

TrustStore(callback=ask_user)  # ask: a sync or async callback gets a CertInfo
TrustStore(trust_on_first_use=False)  # defer: refuse, and record it in store.pending
TrustStore(trust_on_first_use="auto")  # auto: pin without asking (logged)
```

**Defer** suits front ends that can't show a dialog in the middle of a
request (a UI talking to Python over a bridge, or any synchronous caller):
run, show what was refused, pin what the user confirms, run again.

```python
store = TrustStore(trust_on_first_use=False)
async with AsyncSessionRelevanceClient(trust=store) as client:
    results = await client.evaluate("number of bes computers")
for host_port, cert in store.pending.items():  # each came back as tls/untrusted
    if user_confirms(host_port, cert.fingerprint):  # SHA-256, AB:CD:… form
        store.accept(host_port)  # pins it; KeyError if it isn't pending
# run again: accepted hosts now connect
```

A refused certificate comes back as `tls` / `untrusted`, whose message
names the host:port and, when the store recorded the certificate, its SHA-256
fingerprint; `detail` keeps the TLS error and the CLI hint (`--trust-cert`).
The structured certificate is in `store.pending`. `accept()` raises
`ValueError`, and pins nothing, if the host has meanwhile been pinned to a
different certificate: replacing a pin stays a deliberate step
(`--forget-cert` / `KnownCerts.forget`). A callback that declines
records the certificate in `pending` too. `record_refused=False` turns
recording off, and with `trust_on_first_use=False` also skips the bare
handshake that fetches the certificate.

**Auto-accept is opt-in from 1.4.0.** `TrustStore()` with no callback, and
so `AsyncSessionRelevanceClient()` and `evaluate_session_relevance()` with
the default `trust`, still pin any first-use certificate, but now emit a
one-time `DeprecationWarning` asking for one of the choices above. It is
attributed to your line of code, so Python shows it by default in scripts
run directly and under pytest; elsewhere enable it with `-W default` or
`PYTHONWARNINGS=default`. **In 2.0
the default will refuse and record** (defer). `trust_on_first_use="auto"`
keeps today's behaviour without the warning; `True` / `False` keep working.

The CLI asks when interactive, pins automatically (`"auto"`) when not, and
refuses with `--no-tofu`, as before, and never shows the warning. A refused
certificate's message now names its fingerprint (still followed by the
`--trust-cert` hint), and `--no-tofu` fetches the certificate with a bare
handshake to do so. `--show-certs`,
`--trust-cert NAME|HOST:PORT` and `--forget-cert HOST:PORT` manage pins in
`~/.bigfix/.remote_session_known_certs.toml`.

### BigFix Query (ClientQuery, provisional)

`RestBackend` can also send **client** relevance to agents through the root
server's BigFix Query API, and (since 1.3.0) `SaasBackend` through BigFix
SaaS fast query, for tools such as
[bigfix-remote-client-relevance](https://github.com/jgstew/bigfix-remote-client-relevance)
that want this package's config, credentials and certificate pinning. It is
opt-in and separate: `evaluate()` is unchanged. Two calls, and polling is
up to the caller, since rows accumulate as agents answer:

```python
import asyncio

from bigfix_remote_session_relevance import (
    RestBackend, TrustStore, load_config, supports_client_query,
)

conn = next(c for c in load_config().connections if c.backend == "rest")
store = TrustStore(trust_on_first_use=False)  # or a callback, or "auto"
async with RestBackend.from_config(conn, trust=store) as backend:
    assert supports_client_query(backend)  # RestBackend and SaasBackend
    submitted = await backend.submit_client_query("computer name", [<COMPUTER_ID>])
    if submitted.ok and submitted.query_id is not None:
        results = await backend.client_query_results(submitted.query_id)
        for _ in range(30):  # about a minute
            if results.rows or not results.ok:
                break
            await asyncio.sleep(2)
            results = await backend.client_query_results(submitted.query_id)
        for row in results.rows:  # one row per value, per computer
            print(row.computer_id, row.computer_name, row.is_failure, row.result)
```

By default agents evaluate it like qna, with no fixlet or site context, so
`relevant fixlets of sites` fails (`InspectorFixletContextError`). Since 1.3.0,
`submit_client_query(..., use_client_context=True)` asks the agent to
evaluate it in its client context instead (`<UseClientContext>` in the
BESAPI 11.0.7 schema). The default, `None`, leaves the element out, so
servers that predate it see the same request as before.

Errors are results here too (`response.error` is a `ResultError`); only
caller bugs raise (no computer ids, ids that are not integers, or a
`use_client_context` that is not a bool). Operators
who are not master operators need the **Can Submit Queries** permission.
Computers outside the operator's scope are accepted without an error but
never answer, so stop polling on your own timeout.

On BigFix SaaS, a query targets **one** computer. Several ids come back as
an error result (`unsupported_feature` / `multiple_targets`) and nothing is
sent, so submit one query per computer. Ids must be positive (`ValueError`
otherwise: the service would treat `0` as no target, which is every
device). A submit also shows up in the operator's console history, and most
failed submits are a bare HTTP 500, including client relevance the root
server rejects.

### Setup from another tool (provisional)

`run_setup(path=None, *, backends=None)` is the interactive `--setup`
wizard as a function returning its exit code. `path=None` is the usual
config path; `backends=("rest",)` probes, and offers to save, only those
backends.

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
  the parameters in their signatures, keyword names included, except the
  provisional names below. `transport` / `transport_factory` are testing
  hooks typed with httpx's classes and are not covered.
- **Results:** the `SessionRelevanceResult` and `ResultError` fields, the
  `to_dict()` keys and value types, the error kinds (`ERROR_KINDS`) and the
  exception class `raise_for_error()` raises for each.
- **CLI:** flags, the exit codes in the table above, and the `--json` output
  (`to_dict()` per result).
- **Config file:** `schema_version = 1` and the keys and backend names in
  [remote_session_connections.example.toml](remote_session_connections.example.toml),
  where the file is looked for (`--config`, `$BFRSR_CONFIG`,
  `~/.bigfix/.remote_session_connections.toml`) and `BFRSR_LOCAL_ROOT_SERVER`.
  The lenient aliases (`url`, `host`, `user`, `type`, `wr`, …) keep working,
  but may be deprecated, with a warning for at least one minor release first.

**Provisional:** `Backend`, `RestBackend`, `ExplorerBackend`,
`WebReportsBackend`, `SaasBackend`, `TrustStore`, `KnownCerts` and
`CertInfo`, (since 1.1.0) the BigFix Query names `ClientQueryExtras`,
`ClientQueryResponse`, `ClientQueryRow`, `supports_client_query` and
`run_setup`, and (since 1.4.0) `TrustPolicy` and `ServerAddress`, are public and usable, but may change in a minor release (noted
in its release notes). Use the clients for a stable interface.

Additions (a new result field or `to_dict()` key, error kind or code, flag
or config key) come in minor releases. Code that switches on error kinds
or codes should allow ones it doesn't know. `ResultError` itself accepts
only the kinds of the installed version, so check `kind` before rebuilding
one from a newer version's `--json`. Older versions warn about, and ignore,
config keys they don't know.

Not covered: the plain-text CLI layout and summary, stderr and log messages,
error message wording, `detail` and `raw` (the server's own text), the
certificate pin and cache files under `~/.bigfix`, and anything not in
`__all__` (types such as `Pin` or `ServerAddress` that provisional classes
return or take are provisional with them).

## Development

```bash
uv sync
uv run pytest                                  # offline; live tests skip
BFRSR_LIVE_TESTS=1 uv run pytest tests/integration -n0   # against your config
uv run python scripts/capture_fixtures.py      # refresh redacted fixtures
```

See [DESIGN.md](DESIGN.md) for the specification and [AGENTS.md](AGENTS.md)
for contributor notes.
