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
| form, percent-quoted first (besapi) | every query fails: "character which is not allowed", or 400 "Invalid JSON" when the quoted value is still valid JSON (`1`, `true`, `1.5`) | works: the value is URL-decoded twice |
| form, plain (and GET) | works, except a relevance that is itself valid JSON (`123`, `true`, `"x"`): 400 "Invalid JSON" | `+` survives, but `%xx` is decoded twice: `"100%25 done"` gives "improper %-sequence", and `%22` inside a string ends it early |
| `application/json` | 400 "Bad request parameters" | not tested |

No single form encoding works in both states for relevance containing `%`
escapes (and `%22` inside string literals is common), so plain relevance is
sent as `application/json+relevance` first. On that
specific 503 it falls back to besapi's percent-quoted form and keeps using
the form for `EXPLORER_RECHECK_SECONDS` (300 s) before trying JSON again.
If Explorer returns during that window the form fails every query, mostly
with "character which is not allowed"; that error triggers one JSON retry,
and a 503 on the retry means the error was genuine (e.g. `1.5`). **(observed)**
Relevance whose percent-quoted form is still valid JSON (`1`, `true`,
`1.5`) fails differently then, with 400 `{"error":"Invalid JSON: Invalid
required value type, expected type: \"object\""}`, which triggers the same
retry (issue #6). Only errors the server reports count; a garbled body
(`response_format`) is not retried. String literals such as `"hello"` are quoted to `%22…` and
get "not allowed" instead. **(observed)**
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
- **Registered servers (setup only).** `RestBackend.registered_servers()`
  GETs `/api/explorers` and `/api/webreports` (XML) and returns
  `(backend, url)` pairs (an error only if both lists failed). `--setup`
  probes the ones it has not already tried, and only after the user agrees:
  the lists are the root server's word, not the user's, and a listed server
  may be anywhere, over http. `probe()` without `confirm_listed` never sends
  credentials to them.
  **(observed, 11.0.7)** Both need a master operator: anyone else gets `403
  text/plain "Action requires master operator privileges."`
  (`authentication` / `permission_denied`). The list endpoint is the plural
  `/api/explorers` (`/api/explorer/{name}` is one server's details). Each
  entry is `<Explorer Resource="…"><URL>https://HOST:9383</URL></Explorer>` /
  `<WebReports><URL>http://HOST:888</URL></WebReports>`, and the root
  server's own Explorer was listed twice, under its short machine name.
  The lists are the same with Explorer running or stopped: they are what is
  registered, not what is up.
  The `?output=json` Web Reports form also carries each server's `token`, so
  only XML is requested. `evaluate()` never uses these lists.
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
  `FloatingPoint`, `DateTime`, `Tuple` (nested). Every other type seen is
  `<String>`: `date`, `time of day`, `time interval`, `version`, `day of
  week`, `month`, `year`, `day of month`, `month and year` (11.0.7, 2026-10-19;
  captures `date`, `version`, `date_parts`, …). `FloatingPoint` text is the
  same as the REST API's JSON number text, with and without a reachable
  Explorer, and Explorer's (`0.000001234`, `1.0e+300`, `3.0`).
  `DateTime` is ISO 8601
  (`2026-10-17T17:09:32-04:00`) and is converted to the BigFix format the
  other backends return (`Sat, 17 Oct 2026 17:09:32 -0400`), locale
  independently. `evaltime` is in milliseconds (matches REST `evaltime_ms`).
- **(observed, 11.0.7)** Answer text keeps the client qna's escapes, with both
  SOAP methods: `%` is `%25` and 0x00–0x1F and 0x7F are `%xx` in lowercase
  hex (`"a%25b"` → `a%25b`, `"a%09b"` → `a%09b`). Space, `,`, `;`, `"` and
  everything ≥ 0x80 are sent as is. REST and Explorer send the text itself,
  so every text leaf is decoded (`escapes.unescape_answer`, one pass:
  `a%2541` → `a%41`). Error text is not escaped (`error "a%25b%09c"` faults
  with `a%b c`) and is left alone; `raw` stays as sent.
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
- **Numbers are re-encoded** by the gateway as JavaScript numbers (2026-10-19):
  integers above 2**53 lose precision (`9223372036854775807` arrives as
  `9223372036854776000`, `9007199254740993` as `9007199254740992`), and
  floating points use JavaScript's form (`3`, `1e+300`, `1e-7`, `0.3`), not
  BigFix's (`3.0`, `1.0e+300`, `0.0000001`, `0.30000000000000`). BigFix's
  text can't be rebuilt from it, so SaaS answers keep the gateway's text and
  are the one exception to identical answers across backends. A query that
  needs the exact value can ask for `as string`.
- **Email case doesn't matter** to sign-in (2026-10-19: the configured email
  upper-cased signed in to the same account), so the shared sign-in key
  lowercases it: differently cased connections share one session and one
  cached failure.
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
  \"computers\": …"}`, reported as a `session_relevance` error.
- mTLS: no public documentation was found; the client certificate is loaded
  into the TLS context (`client_cert`, `client_key`,
  `client_key_password_env`) and works with or without Basic auth.

### BigFix Query (ClientQuery)

Opt-in and additive, like the Explorer extras: `ClientQueryExtras`
(`backends/client_query.py`), implemented by `RestBackend` and (since
1.3.0) `SaasBackend`. It sends **client** relevance (the parameter is
`client_relevance`), so it never shares a code path with `evaluate()`. The
argument checks and `ClientQueryResponse` building live in `client_query.py`,
so both backends behave the same to a caller.

- `submit_client_query(client_relevance, computer_ids)`: `POST
  /api/clientquery`, `Content-Type: application/xml`, body
  `<BESAPI><ClientQuery><ApplicabilityRelevance>true</ApplicabilityRelevance><QueryText>…</QueryText><Target><ComputerID>…</ComputerID>…</Target></ClientQuery></BESAPI>`
  built with ElementTree, so the text is XML-escaped. **(observed)** `<`, `&`
  and `%22` reach the agent intact (`results_escaped`). No computer ids, or
  ids that are not integers, raise: a caller bug.
- `submit_client_query(..., use_client_context=True|False)` adds
  `<UseClientContext>true|false</UseClientContext>` between `QueryText` and
  `Target` (the BESAPI 11.0.7.61 schema makes `ClientQuery` an
  `xs:sequence`, so order matters). Without it agents evaluate like qna, with
  no fixlet or site context. The default `None` omits the element, so the
  body is byte-for-byte the 1.2.0 one for servers that predate it. A
  non-bool (`1`, `"false"`) raises `TypeError`. **(observed, through BigFix
  SaaS, whose bfproxy sends this same XML to its root server)** with it
  `values of headers "X-Fixlet-Source-Release-Date" of relevant fixlets of
  sites` answered 135 rows; without it, one `isFailure` row "The expression
  could not be evaluated: class InspectorFixletContextError". The results'
  shape does not change. Which on-prem server versions accept it is not
  confirmed (the schema that has it is 11.0.7.61).
- **(observed)** The answer's `<ClientQuery Resource="http://…:52311/api/clientquery/N">`
  is `http://` for an https request, so only `<ID>` is read (with defusedxml).
- `client_query_results(query_id)`: `GET /api/clientqueryresults/{id}?output=json`.
  **(observed)** The JSON comes with no Content-Type: `{"results": [{"computerID",
  "computerName", "subQueryID", "isFailure", "result", "ResponseTime"}]}`.
  Rows accumulate as agents report (`{"results": []}` right after submit);
  every row so far is returned and polling is the caller's. A plural answer
  is one row per value, all with the same computer; a failed evaluation is a
  row with `isFailure: true` and the error text in `result`. **(observed)** An
  empty plural answer and `""` are both one row with `result: ""`
  (`results_empty_plural`, `results_empty_string`): the API cannot tell
  them apart.
- **(observed)** Computer ids outside the operator's scope are accepted
  silently: the submit is a 200 with a query id, and those computers never
  add a row (two of three targeted ids in the capture run, both real computers
  in the deployment, as the operator could not see them). No row is not an
  error, so a caller polls until its own timeout; checking the ids first with
  session relevance (`ids of bes computers`, scoped the same way) avoids that.
- Both run through `Backend._with_trust`, the same credential, TOFU and
  error-mapping path as `evaluate()` (which `_run_with_trust` now wraps), and
  return a `ClientQueryResponse` (`query_id`, `rows`, `error`, `connection`,
  `server`, `backend`, `elapsed_ms`). A 401/403 that mentions a permission is
  `authentication` / `permission_denied`. Any 403 notes that non-master
  operators need "Can Submit Queries", since bad REST credentials are a 401
  (no 403 has been captured yet; the tests use synthetic bodies). Other
  non-200s are `http` with the server's text in the message: **(observed)**
  `400 "cannot get results for queries not submitted by the logged user"` for
  another operator's or an unknown id. Unparsable bodies are `response_format`.

#### On BigFix SaaS (fast query)

**(observed 2026-10-26)** on one Windows agent (client 11.0.5.204); captures
in `tests/fixtures/saas/captured/clientquery/`. Request shapes are also in
be-bfproxy-service `src/helpers/requests.js` and `src/v1/routes/clientquery.yaml`.

- `submit_client_query`: `POST /core/v2/clientquery/create` (the usual
  envelope, `sid` top-level) with `data = {queryText, applicabilityRelevance:
  "true", useClientContext?, target: {computerId: N}}` →
  `{"data": {"clientQueryId": "2"}}`, a string read as an int. bfproxy turns
  it into the same `<BESAPI><ClientQuery>` XML REST sends, as a non-master
  operator. `queryTitle` / `description` / `category` / `parameters` would
  make it a saved query, so none are sent. Core also keeps it in the
  operator's console history.
- **One computer per query.** `target` takes one of `computerId` (a single
  integer in the route schema) / `computerName` / `customRelevance` /
  `computerGroup`. **(observed)** A `customRelevance` target got no answer in
  two minutes, whether `exists (N; 1) whose (it = computer id)` or just
  `computer id = N`, from the agent that answered `computerId: N` in about
  9 s. So several ids (after removing duplicates) are an error result,
  `unsupported_feature` / `multiple_targets`, sent nowhere: not a raise,
  since REST accepts them and callers written against `ClientQueryExtras`
  must keep working. bfproxy drops a falsy `computerId`, leaving no target
  (every device), so ids ≤ 0 raise `ValueError` (a caller bug).
- Core answers 400 for a body it cannot parse, 403 for a `sid` the operator
  may not use and 409 for a duplicate saved-query title, but every upstream
  failure (from bfproxy or the root server) is a bare 500, possibly after it
  submitted to the root server, so a submit is never resent, except once
  after a 401 (the gateway refusing the cookie before core sees the request,
  the same renewal `evaluate()` does). The 500's message says why it is
  uninformative. No error bodies are captured yet.
- `client_query_results`: `POST /bfproxy/v1/clientquery/listresults` with
  `data = {queryId: "<id>", start, count: 1000, stats: true}` →
  `{results: [{computerId, computerName, subQueryId, isFailure, result,
  responseTime}], totalResults, agentCount}`, `{"results": [], "totalResults":
  0, ...}` until the agent answers. It pages until a page is short (fewer
  than `count` rows) or it has `totalResults` rows; a short page ends it even
  if the total grew meanwhile, and without a total only a short page does.
  As on REST it is all or nothing: an error on any page drops every row.
  Offset paging assumes rows keep their order while agents answer; only a
  finished answer was observed paging.
  **(observed)** Pages of 50 over a 135-row answer returned the same rows,
  in the same order, as one page of 1000. As on REST, a plural answer is one
  row per value and an empty value is a `""` row; only the id key's case
  differs (`computerId`).

## The result contract

`SessionRelevanceResult` (frozen dataclass). The field set is pinned by
`test_result_has_every_designed_field`; adding a field means updating that
test, `to_dict()` and this section.

Names always say *session* relevance: the field, the `to_dict()` key, the
`session_relevance` / `session_relevances` parameters of every `evaluate*`
method and the error kind. Client relevance is a different dialect
(bigfix-remote-client-relevance says `client_relevance`), so the public API
never uses a bare `relevance`. Wire bodies keep the server's own `relevance`
key.

| Field | Meaning |
|---|---|
| `session_relevance` | the query |
| `answers` | native values, coerced by `type`: `integer`→`int`, `boolean`→`bool`, tuples→`tuple`, otherwise `str` (a `floating point` is the server's text, e.g. `"0.000001234"`, never re-formatted by Python; a number with no type to coerce it, e.g. in an Explorer `keys` dict, stays a `float`); `dict` only from Explorer `keys` |
| `answer_strings` | BigFix-style strings; tuples joined with `", "` |
| `type`, `plural`, `evaluation_time_ms` | as reported by the server (`None` if unknown) |
| `error` | `ResultError` or `None` |
| `connection`, `deployment_id`, `backend`, `server` | where it came from (no credentials) |
| `elapsed_ms` | round trip (excluded from equality) |
| `raw` | `RawResponse(status_code, content_type, text, format)`; excluded from `repr`, equality and `to_dict()` unless `include_raw=True` |

String answers are the text the session relevance evaluates to, on every
backend (Web Reports' `%xx` escapes are decoded; see § Web Reports SOAP).
**(observed, 11.0.7)** REST (with and without a reachable Explorer),
Explorer and SaaS send that text already decoded (captures `escaped_*`;
SaaS checked live).
`unescape=False` on any `evaluate*` method (CLI `--keep-escapes`) asks for
the escaped form instead: `%` and 0x00–0x1F/0x7F as lowercase `%xx`, which is
what Web Reports and the client's qna print, and makes control characters
visible. The client applies `escape_answer` to every string in `answers`
(tuple members and Explorer `keys` values included) and rebuilds
`answer_strings`. It does this after the backend has answered, so the
escaped form is the same whichever backend answered, and no backend's
`evaluate()` changes. Errors and `raw` are never escaped.
`escape_answer`, `unescape_answer` and `escape_result` (the same step for a
`SessionRelevanceResult` from a backend used directly) are exported. For Web
Reports' text `escape_answer(unescape_answer(t)) == t`, checked live on
11.0.7 for every character class the issue #5 probes cover. `unescape_answer`
decodes any `%XX`, not only the characters Web Reports escapes, so it is not
meant for arbitrary text.

### Errors

Per-query failures are results, never exceptions. `raise_for_error()` (or
`raise_errors=True`) converts them to one exception class per kind
(`session_relevance` raises `SessionRelevanceEvaluationError`).

| `kind` | When | `code` examples |
|---|---|---|
| `session_relevance` | the server evaluated it and said no | |
| `authentication` | credentials rejected (message `credentials rejected`), or accepted but missing a privilege, or the local root server credentials are unavailable | `permission_denied`, `local_credentials_absent`, `local_credentials_unreadable`, `local_credentials_decrypt_failed`, `local_credentials_incomplete` |
| `connection`, `timeout` | unreachable | |
| `tls` | certificate problems | `cert_verify_failed`, `untrusted`, `pin_mismatch`, `pinned_cert_invalid`, `client_cert`, `tls_handshake` |
| `http` | other statuses | `service_unavailable` |
| `response_format` | not the expected JSON/XML (e.g. a login page) | |
| `unsupported_feature` | Explorer extras on a deployment without Explorer access; a BigFix SaaS fast query with several computer ids | `multiple_targets` (SaaS fast query) |

Session relevance error messages are normalized (`Error:` prefixes, whitespace) so
the same bad query reads the same on every backend; `detail` keeps the
server's text. **(observed, 2026-10-19)** An evaluation exception is
`class TooLargeForStandardNotation` on-prem but `27TooLargeForStandardNotation`
on BigFix SaaS (a mangled C++ type name: its length, then the name); the SaaS
form is rewritten to the on-prem one, only when the number equals the name's
length (capture `error_too_large`).

## Fan-out, grouping and failover

- **Deployment id** = `sha256 of gather url of bes license`, asked of each
  connection. If a server lacks `sha256 of <string>`, the gather URL is
  hashed locally (UTF-8, lowercase hex): **(observed)** the two agree on REST
  and Web Reports. A Web Reports server returning several ids (several
  datasources) gets `multi:` + sha256 of the sorted ids, so it is never treated
  as a duplicate of one deployment. Any answer that is not 64 hex digits
  (after trimming and lowercasing) means no id: it is server text that would
  be printed, written to the config and used for grouping. Discovered ids
  are written back to the config (tomlkit keeps comments) and trusted on
  later runs.
- **`per_deployment`** (default): one group per deployment id (a connection
  without one is its own group). Groups run concurrently. Within a group,
  connections are tried in `backend_preference` order (explorer, rest,
  webreports, saas), then config order, and the first that works stays first.
- Failover happens on `connection`, `timeout`, `tls`, `authentication`,
  `http` and `response_format`. **Never** on
  `session_relevance`
  (the query would fail everywhere) and **never** on `pin_mismatch` /
  `pinned_cert_invalid` (a possible impostor is a security signal, not an
  outage). A group where everything failed returns one result, preferring a
  non-unreachable error, with every connection tried listed in the message.
- **`all`**: every enabled connection, each result returned.
- **Streaming**: `evaluate_stream` / `evaluate_explorer_stream` yield the
  same results in completion order; the batch forms return them in group
  (or connection) order. Deployments whose ids are already known start at
  once; only connections still being discovered wait for discovery, and a
  known deployment whose connections all fail waits for it too, since a
  newly discovered connection may be its failover. Abandoning a stream
  cancels the queries still running. `result_count()` says how many results
  to expect, or `None` while that depends on undiscovered ids (the CLI then
  holds its first answer until it knows whether to label sections).
  Interactive prompts and streamed output share one lock, so answers never
  land in the middle of a password or certificate prompt.
- **CLI summary**: after a labelled plain-text run, results with identical
  answers, answer type and error (ignoring the connections a failover
  tried) are collapsed, most common first. Printed
  to stdout only when something collapses. Unreachable results hidden
  without `-v` are left out of it.
- **CLI terminal safety**: answer text, error messages and the answer type
  come from the server. When the plain-text output goes to a terminal
  (`isatty()`, checked per stream), the renderer passes them through
  `escapes.escape_controls`: C0 controls except tab, DEL and C1 (0x80–0x9F)
  become `%xx`, so server data can't send terminal escape sequences (ESC,
  CSI) or fake extra answer lines (LF, CR, NEL). Error messages keep LF: an
  error is one message on stderr. `%` is not escaped, to keep text such as
  `%SystemRoot%` readable, so the display is lossy; `--keep-escapes` is the
  unambiguous form. Output to a pipe or file is unchanged, for scripts.
  This is display only: `answers`, `answer_strings`, `--json` and `--raw`
  are never changed, and neither is any backend's `evaluate()`.
  Other server text is escaped too, terminal or not, since it is only ever
  read by a person: setup-wizard probe messages, and the deployment ids that
  `--show-config` and `--discover-deployments` print (one configured or
  cached before ids were checked can hold server text). A cached local root
  server id that isn't id-shaped is ignored, and BigFix SaaS server ids
  (`sid`) that aren't plain names (`[0-9A-Za-z_-]+`) are skipped. The CLI
  switches stdout/stderr to `errors="backslashreplace"` unless their handler
  can't fail (`replace`, `ignore`, `xmlcharrefreplace`, `namereplace`), so an
  answer the encoding can't hold (a lone surrogate from a JSON `\ud800`, or
  text a non-UTF-8 console can't show) prints as `\uXXXX` instead of ending
  the run. `strict` and `surrogateescape` (CPython's default in UTF-8 mode
  and the C locale, which refuses `\ud800` too) are both replaced, even when
  set through `PYTHONIOENCODING`.

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
`client_cert`, mTLS over http, `credentials = "local_root_server"` on anything
but `rest` or alongside other credentials. With no config file, besapi's `BES_ROOT_SERVER` /
`BES_USER_NAME` / `BES_PASSWORD` or `~/.besapi.conf` become one `rest`
connection.

Password resolution: `password_env`, then `password`, then an interactive
prompt, else an `authentication` error without any request.

### Local root server credentials

On a BigFix root server, `load_config` adds one more `rest` connection,
`local-root-server`, with `credentials = "local_root_server"`: its server,
username and password are the server's own REST API credentials
(`local_root_server.py`, a minimal reimplementation of besapi's
`plugin_utilities_linux` / `plugin_utilities_win`). Session relevance is
read-only, so these are used without opting in, as besapi does.

- **Linux:** `/var/opt/BESServer/Applications/MasterOperatorCredentials`, a
  header-less `Key=Value` file (each line stripped, split on the first `=`,
  key case kept) with `RESTUsername`, `RESTPassword={aes,1}…` and
  `RESTURL=https://localhost:52311/api`. Normally readable by root only.
  The password is `CryptoUtility -d -i <value>` (argv list, no shell, 30 s
  timeout), stripped stdout.
- **Windows:** `HKLM\SOFTWARE\Wow6432Node\BigFix\Enterprise Server\MFSConfig`
  (`RESTUsername`, `RESTURL`, `RESTPassword`) via `winreg`. The password is
  `{obf}` + base64 of a machine-scope DPAPI blob, decrypted with
  `CryptUnprotectData` (flags 4) through ctypes, so there is no pywin32
  dependency.
- A trailing `/api` is dropped from `RESTURL`. A decrypted password of 3
  characters or fewer counts as a failed decryption (as in besapi).
- `load_config` checks presence (file exists and is readable / the registry
  key opens) and reads `RESTURL` as the connection's `server`, so
  `--show-config` and `--trust-cert` see the real address; it never
  decrypts. If the credentials exist but this user cannot read them, the
  connection is skipped (logged at INFO) when anything else is configured,
  and kept otherwise so the error explains what to do.
- The password is decrypted on the backend's first query, once, in a thread
  (`asyncio.to_thread`): CryptoUtility may take seconds and must not block
  the event loop. If that fails and other connections are selected, the
  client leaves the automatic connection out (logged at WARNING) instead of
  turning every run partial; alone, or written in the file, its error is
  returned.
- Every failure is an `authentication` result, sent without any request,
  with a `code`: `local_credentials_absent` (not a root server),
  `local_credentials_unreadable` (run as root / Administrator),
  `local_credentials_decrypt_failed` (CryptoUtility or DPAPI failed),
  `local_credentials_incomplete` (a value is missing or `RESTURL` is unusable).
  The plaintext and CryptoUtility's output are never logged or put in a
  message.
- Not added when `BFRSR_LOCAL_ROOT_SERVER` is `0`/`false`/`no`/`off`, when
  `[defaults] local_root_server = false`, or when the file already has a
  connection with `credentials = "local_root_server"` (to name or tune it;
  only `backend = "rest"`, with no other credentials) or named
  `local-root-server`. Such a connection takes no `server`, `username`,
  `password` or token: `RESTURL` decides where the credentials go. The
  automatic connection is never written to the file; its discovered
  deployment id is kept, with its server, in
  `~/.bigfix/.remote_session_local_root_server.toml` (0600) and reused only
  for that server.

## Compatibility

From 1.0.0 the public surface follows semantic versioning; README §
Compatibility lists what that covers and which names are provisional (the
backend and trust classes). Tests pin the parts most easily changed by
accident: `test_result_has_every_designed_field` (the result fields),
`test_error_kinds_are_the_designed_set` (the error kinds and their order),
`test_public_names.py` (`__all__` as a snapshot, the provisional set,
session relevance naming of every public `evaluate*` parameter, and
`client_relevance` for the BigFix Query methods), and
`test_exit_codes_are_the_documented_values`. A new field, kind or error code is additive;
renaming or removing one is a major version. `test_packaging.py` keeps the
Python classifiers equal to the versions CI tests.

## Open questions

- **SaaS:** what the gateway does with no `sid` on an account with several
  servers (setup does not rely on it; only one-server accounts were seen
  live). Logout on close is not sent (v1 sessions are not counted against
  the cap).
- Whether the second URL decode on the no-Explorer path (confirmed live:
  `%xx` only, not `+`) happens in the root server or in the Web Reports it
  forwards to. It does not change what the client must send.
- Whether a multi-datasource Web Reports really returns several gather URL
  hashes.
