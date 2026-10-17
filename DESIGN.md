# Design

The specification for bigfix-remote-session-relevance: what it promises and
why it is built the way it is. Facts marked **(observed)** come from
responses captured from a BigFix 11 deployment (redacted, under
`tests/fixtures/*/captured/`). Where they contradict developer.bigfix.com,
the observed behaviour wins and the code says so.

## Backends

| Backend | Request | Wire format | Auth | Default |
|---|---|---|---|---|
| `rest` | `POST /api/query`, form `relevance` + `output=json` | JSON (XML fallback) | Basic or bearer token | https, 52311 |
| `explorer` | `POST /api/relevance`, JSON `{"relevance": …}` | JSON | Basic, bearer token, or mTLS | https, 9383 |
| `webreports` | `POST /webreports/soap`, `GetStructuredRelevanceResult` | SOAP XML | `LoginHeader`, then `AuthenticateHeader` + session token | https, 443 |
| `saas` | `POST https://api.bigfix.com/bfproxy/v2/relevance`, JSON envelope `data: {"query": …}` | JSON | email/password (+ TOTP) → session cookies | https, 443 (`login.` → `api.`) |

`server` is normally a bare host. https and the default port are assumed;
only a different scheme or port is written. A trailing `/api` is stripped
(as besapi does); credentials in the URL are rejected.

### REST API

**(observed)** How `/api/query` treats the relevance depends on whether the
root server can reach a BigFix Explorer, because with one it forwards the
query there:

| Request | Explorer reachable | No Explorer |
|---|---|---|
| `application/json+relevance` body `{"relevance": …}` | evaluated exactly | 503 "no reachable BigFix Explorer…" |
| form, percent-quoted first (besapi) | every query fails: "character which is not allowed" | works: the value is URL-decoded twice |
| form, plain (and GET) | works, except a relevance that is itself valid JSON (`123`, `true`, `"x"`): 400 "Invalid JSON" | `+` survives, but `%xx` is decoded twice: `"100%25 done"` gives "improper %-sequence", and `%22` inside a string ends it early |
| `application/json` | 400 "Bad request parameters" | not tested |

No single form encoding works in both states for relevance containing `%`
escapes (and `%22` inside string literals is common), so plain relevance is
sent as `application/json+relevance` first. On that
specific 503 it falls back to besapi's percent-quoted form and keeps using
the form for `EXPLORER_RECHECK_SECONDS` (300 s) before trying JSON again.
If Explorer returns during that window the form fails every query with
"character which is not allowed"; that error triggers one JSON retry, and a
503 on the retry means the error was genuine (e.g. `1.5`). **(observed)**
With Explorer registered but down, every REST query takes ~3 s (JSON 503 and
form alike): the root server waits for Explorer before answering itself.
Both paths are verified live: `+`, `&`, `<`, `'`, `\`, `/`, `?`, `#` round-trip,
and `%22` inside a string literal is relevance's own escape for `"`. Answers
are identical on both paths; only `evaltime_ms` precision and the extra `count`
field differ.
- **(observed)** Relevance errors are `{"result": [], "error": "…"}` with HTTP
  200, so the error is checked *before* the result.
- **(observed)** No `Content-Type` header on JSON responses: the format is
  sniffed from the body.
- **(observed)** Bad credentials: `401 text/plain "HTTP 401: Unauthorized"`.
  A session cookie from an earlier login is honoured even when later
  requests carry the wrong password.
- Explorer extras use the same `application/json+relevance` request, with no
  fallback. **(observed)** With no Explorer available: `503 text/plain "Cannot
  perform relevance query evaluation at this time because there is no reachable
  BigFix Explorer instance…"` (`http` / `service_unavailable`).

### Web Reports SOAP

- `GetStructuredRelevanceResult` is used first: it reports `type`, `plural`
  and `evaltime`, so results match the other backends. On a fault that says
  the operation is unsupported, the backend switches to `GetRelevanceResult`
  for its lifetime (string answers; plurality from the answer count: one is
  singular, zero or several plural).
- **(observed)** The session header type is **`AuthenticateHeader`** (from the
  server's WSDL). developer.bigfix.com says `AuthenticationHeader`, which the
  server rejects: "type 'AuthenticationHeader' specified in 'xsi:type' cannot
  be resolved". Any fault while using a token triggers one fresh login.
- **(observed)** Structured relevance errors are an `<error>` element, HTTP
  200. Plain-method errors and bad logins are SOAP Faults, also HTTP 200
  ("Invalid username or password.").
- **(observed)** Typed result elements: `Integer`, `String`, `Boolean`,
  `DateTime`, `Tuple` (nested). `DateTime` is ISO 8601
  (`2026-10-17T17:09:32-04:00`) and is converted to the BigFix format the
  other backends return (`Sat, 17 Oct 2026 17:09:32 -0400`), locale
  independently. `evaltime` is in milliseconds (matches REST `evaltime_ms`).
- **(observed)** The WSDL advertises `/soap` as the address; `/webreports/soap`
  (the documented path) works too.
- http:// is allowed (some Web Reports run plain http) but logged once per
  connection: the password travels in the envelope.

### BigFix SaaS

All **(observed)** on 2026-10-17 (live login, the service's OpenAPI spec, and
the bigfix-saas MCP server, which makes the same choices).

- `server` is the web UI host (`login.bigfix.com`, `eulogin.bigfix.com`) or the
  API host; requests go to the API host (`login.` → `api.`, `eulogin.` →
  `euapi.`). Because the login POST carries the password, only https hosts
  with those four prefixes are accepted, at config load and in the backend.
- Every request is a POST of `{"requestId": uuid4, "timestamp": "<epoch ms>",
  "data": …}`, plus an optional `sid` (`"bf"` + digits, config key `sid`) that
  selects a BigFix server, with the header `x-bfnow-csrf-protection: 1`.
  Without the header: `403 "CSRF Protection Header Missing"`. A reused
  `requestId` is a replay: `409 {"error": "Request conflict"}`. Responses are
  `{"status", "message", "data"}`; envelope errors carry `data.errorMessage`.
- Sign-in: `/auth/v1/user/login` with `{email, password[, totp]}`. The
  session is the `accessToken` / `refreshToken` cookies (HttpOnly, Secure);
  the body has `iat`/`exp` and the account's servers under `data.pids.bf`.
  **v1, not v2:** v1 does not register a gateway session (v2 counts against a
  5-concurrent-session cap, and a v2 login here hung for 30 s).
- Renewal: `/auth/v1/token/refresh` (no data) before `exp` (lifetime from
  `exp - iat`, timed on the local clock) or after a 401, then one fresh login
  if refresh fails. The refresh token appears to be single-use.
- **Lockout safety:** 100 failed logins lock the account for good, so a
  rejected login is cached and never sent again by that backend, or by any
  connection sharing its sign-in (`authentication` / `login_failed`). Known
  signals become codes: `totp_required` (answered through the interactive
  prompt when there is one), `activate_mfa_required`,
  `password_change_required`, `mfa_mismatch`,
  `max_concurrent_sessions_reached`.
- Answers are typed like the REST API's:
  `{"data": {"answer": [...], "evaltime", "count", "plural", "type"}}` (tuples
  as nested arrays, times in BigFix format, `evaltime` in ms); relevance errors
  are `{"data": {"error": "…"}}` with HTTP 200. `/bfproxy/v1/relevance` answers
  identically.
- No Explorer extras: `prefilter` takes BigFix's criteria DSL, not relevance
  strings, so it does not fit `ExplorerExtras`.
- **Setup:** `--setup` treats an https `login.` / `eulogin.` / `api.` /
  `euapi.` host under `bigfix.com` as SaaS (other allowlisted hosts are
  configured by hand) and asks for an email instead of a username. It signs in
  **once**, through one `SaasBackend` (so a rejected login is never resent),
  prompting for a TOTP code only when the service answers `totp_required`, and
  evaluates `sha256 of gather url of bes license` to record `deployment_id`. A
  rejected sign-in is reported and nothing is saved (saving it would resend
  the password on every run). Connections are saved with `verify = true`: the
  service is CA-signed, so trust on first use would only ever pin an
  intercepting proxy.
- **Several BigFix servers (decision):** when `data.pids.bf` lists more than
  one server, setup asks each one (setting `sid` on the same signed-in
  backend, so still one login) and saves **one connection per `sid`**, each
  with its own `deployment_id`. An account with one server is saved without
  `sid` (the gateway's default is that server). The client does **not**
  expand a sid-less connection into one group per server: a connection is one
  endpoint everywhere else (its name in results, `--connection`, the recorded
  `deployment_id`, failover), and expanding would need a login before
  grouping.
- **One sign-in per account (decision):** connections with the same API host,
  email and password share one `SaasSession` (cookies, expiry, the account's
  servers, a cached login failure), held in a `SaasSessionPool` that
  `AsyncSessionRelevanceClient` owns. A lock makes concurrent connections wait
  for a single login (and a single TOTP prompt) and reuse its success or its
  failure, so N servers cost one login per client, and a wrong password one
  failure. Renewal is shared the same way: a 401 triggers one refresh, and a
  connection whose 401 came from cookies another one has already renewed just
  retries with the new cookies. Each connection keeps its own HTTP client and
  `sid`; the cookies are copied into it. The password is part of the key (as
  a SHA-256 digest), so a connection with a different password signs in on
  its own. A `SaasBackend` used directly, without a pool, keeps its own
  session as before. A 5xx answer to the login is not cached (it may be
  transient), so each waiting connection may try once more.

### BigFix Explorer

- **(observed)** While starting, or with no valid connection to its root
  server, Explorer answers POSTs with `405 "Only HTTP GETs are allowed."` or
  `401 {"error": "This API is temporarily unavailable while the connection to
  the Root Server is being re-established."}`, and reports its state on
  `GET /` (`{"status": "Starting", "rootServerConnection": "Invalid Explorer
  Certificate"}`). Both are `http` / `service_unavailable` (not
  `authentication`), with that status in the message.
- **(observed)** An operator without Explorer's login permission gets
  `401 {"error": "Explorer login permission required"}`: `authentication` /
  `permission_denied`, with the server's reason in the message.
- **(observed)** `GET /` returns a JSON status only while Explorer is starting
  or disconnected; once healthy it is a 404 HTML page.
- **(observed)** Success and error JSON have the REST shape (plus `count`).
  Bad credentials: `401 {"error": "Invalid credentials"}`.
- **(observed)** `keys` is written in braces, `{id name {label flag}}`, and
  nests objects. A filter must *return a set*, e.g. `{"computers": "set of (bes
  computers whose (…))"}`. Otherwise the result is `400 {"error": "Filter
  \"computers\": …"}`, reported as a `relevance` error.
- mTLS: no public documentation was found; the client certificate is loaded
  into the TLS context (`client_cert`, `client_key`,
  `client_key_password_env`) and works with or without Basic auth.

## The result contract

`SessionRelevanceResult` (frozen dataclass). The field set is pinned by
`test_result_has_every_designed_field`; adding a field means updating that
test, `to_dict()` and this section.

| Field | Meaning |
|---|---|
| `relevance` | the query |
| `answers` | native values, coerced by `type`: `integer`→`int`, `boolean`→`bool`, tuples→`tuple`, otherwise `str`; `dict` only from Explorer `keys` |
| `answer_strings` | BigFix-style strings; tuples joined with `", "` |
| `type`, `plural`, `evaluation_time_ms` | as reported by the server (`None` if unknown) |
| `error` | `ResultError` or `None` |
| `connection`, `deployment_id`, `backend`, `server` | where it came from (no credentials) |
| `elapsed_ms` | round trip (excluded from equality) |
| `raw` | `RawResponse(status_code, content_type, text, format)`; excluded from `repr`, equality and `to_dict()` unless `include_raw=True` |

### Errors

Per-query failures are results, never exceptions. `raise_for_error()` (or
`raise_errors=True`) converts them to one exception class per kind.

| `kind` | When | `code` examples |
|---|---|---|
| `relevance` | the server evaluated it and said no | |
| `authentication` | credentials rejected (message `credentials rejected`), or accepted but missing a privilege | `permission_denied` |
| `connection`, `timeout` | unreachable | |
| `tls` | certificate problems | `cert_verify_failed`, `untrusted`, `pin_mismatch`, `pinned_cert_invalid`, `client_cert`, `tls_handshake` |
| `http` | other statuses | `service_unavailable` |
| `response_format` | not the expected JSON/XML (e.g. a login page) | |
| `unsupported_feature` | Explorer extras on a deployment without Explorer access | |
| `not_implemented` | reserved for a backend type that exists in the schema but is not built | |

Relevance error messages are normalized (`Error:` prefixes, whitespace) so
the same bad query reads the same on every backend; `detail` keeps the
server's text.

## Fan-out, grouping and failover

- **Deployment id** = `sha256 of gather url of bes license`, asked of each
  connection. If a server lacks `sha256 of <string>`, the gather URL is
  hashed locally (UTF-8, lowercase hex): **(observed)** the two agree on REST
  and Web Reports. A Web Reports server returning several ids (several
  datasources) gets `multi:` + sha256 of the sorted ids, so it is never treated
  as a duplicate of one deployment. Discovered ids are written back to the
  config (tomlkit keeps comments) and trusted on later runs.
- **`per_deployment`** (default): one group per deployment id (a connection
  without one is its own group). Groups run concurrently. Within a group,
  connections are tried in `backend_preference` order (explorer, rest,
  webreports), then config order, and the first that works stays first.
- Failover happens on `connection`, `timeout`, `tls`, `authentication`,
  `http`, `response_format` and `not_implemented`. **Never** on `relevance`
  (the query would fail everywhere) and **never** on `pin_mismatch` /
  `pinned_cert_invalid` (a possible impostor is a security signal, not an
  outage). A group where everything failed returns one result, preferring a
  non-unreachable error, with every connection tried listed in the message.
- **`all`**: every enabled connection, each result returned.

## TLS: trust on first use

`verify = "tofu"` (default), `true` (CA only), `false` (logged), or a CA
bundle path.

1. CA validation first (system store and certifi); a CA-valid cert is never
   pinned.
2. Otherwise the leaf cert is fetched with a bare handshake (no request, no
   credentials), shown to the trust callback (the CLI prompts with the SHA-256
   fingerprint; prompts are serialized), and pinned in
   `~/.bigfix/.remote_session_known_certs.toml` (0600, filelock, atomic
   writes). The library with no callback pins automatically and logs a
   WARNING (classic TOFU); `--no-tofu` / `trust_on_first_use=False` refuses.
3. A pinned host gets an `SSLContext` whose only trust anchor is the pinned
   cert (`VERIFY_X509_PARTIAL_CHAIN`, no hostname check, because BigFix certs
   rarely match the URL). OpenSSL rejects any other cert during the
   handshake, before any Authorization header or SOAP password is sent.
   `tests/unit/test_trust.py` proves this against a real local TLS server.

## Async and sync

The core is async (httpx). `SessionRelevanceClient` runs the async client on
an anyio blocking portal (its own loop, in a thread), so the sync API also
works inside a running event loop.

## Configuration

`--config`, then `$BFRSR_CONFIG`, then `~/.bigfix/.remote_session_connections.toml`.
Read and written with tomlkit. Lenient aliases (`url`/`host`, `type`, `user`,
`api_key`…) because people write these by hand; unknown keys are warned about,
not fatal. Validation rejects: duplicate names, unknown backends, bad servers,
token *and* basic together, a token on Web Reports, `client_key` without
`client_cert`, mTLS over http. With no config file, besapi's `BES_ROOT_SERVER` /
`BES_USER_NAME` / `BES_PASSWORD` or `~/.besapi.conf` become one `rest`
connection.

Password resolution: `password_env`, then `password`, then an interactive
prompt, else an `authentication` error without any request.

## Open questions

- **SaaS:** what the gateway does with no `sid` on an account with several
  servers (setup does not rely on it; only one-server accounts were seen
  live). Whether the service treats email case-insensitively (the shared
  sign-in key compares it exactly, so differently cased connections sign in
  separately). Logout on close is not sent (v1 sessions are not counted
  against the cap).
- Whether the second URL decode on the no-Explorer path (confirmed live:
  `%xx` only, not `+`) happens in the root server or in the Web Reports it
  forwards to. It does not change what the client must send.
- `GetStructuredRelevanceResult` element names for other types (`Float`?,
  dates without time, versions) beyond those observed.
- Whether a multi-datasource Web Reports really returns several gather URL
  hashes.
