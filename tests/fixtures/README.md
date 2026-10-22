# Test fixtures

Files named `doc_*` are **doc-derived**: built from the examples on
developer.bigfix.com, not captured from a server. They pin the documented
shape. Files under `*/captured/` are real responses captured with
`scripts/capture_fixtures.py` and redacted (hostnames, usernames, session
tokens and gather URLs replaced). When the two disagree, the captured file
wins and the parser follows it.

REST captures without a prefix were taken while the root server had no
reachable Explorer; `rest/captured/via_explorer__*` were taken with one, and
`rest/captured/forwarded_*` / `explorer/captured/extras_*` are Explorer
`keys`/`filters` responses. See DESIGN.md § REST API for why both REST
states are kept. The capture script writes REST files unprefixed, so rename
captures taken with Explorer reachable (a `"count"` key in the JSON) to
`via_explorer__*`. Cases first captured with Explorer reachable exist only
in that form; their tests skip the no-Explorer source.

`saas/captured/*.json` are BigFix SaaS (`api.bigfix.com`) relevance response
bodies, captured through the bigfix-saas MCP server and a live login at
first and now with `scripts/capture_fixtures.py --backend saas` (no
wrong-password probe, since failed logins count toward a permanent lock;
`deployment_id.json` is a synthetic id the script never overwrites).
`saas/shape_login_ok.json` copies the observed login response
*structure* with synthetic values; the real one carries the session only in
`accessToken` / `refreshToken` cookies.

`rest/captured/clientquery/` are BigFix Query (`/api/clientquery`,
`/api/clientqueryresults`) responses from an 11.x root server, captured by
hand (the capture script only sends session relevance). The answering
computer is redacted to id `1000001` / `COMPUTER-1` and the server address
to `bigfix.example.com`. The 403 permission case has no capture yet; its
test uses a synthetic body.

`rest/captured/discovery/` are the root server's lists of registered
Explorer and Web Reports servers (`/api/explorers`, `/api/webreports`,
11.0.7, Explorer reachable, hence `via_explorer__`). The 200s need a master
operator and were pasted by hand from the lab (content type not recorded,
so `null`). The lab's machine name is redacted to `ROOTSERVER`, its FQDN to
`bigfix.example.com` and its IP by `redact()`; the repeated Explorer entry is
real. `via_explorer__explorers_json` is the `?output=json` form, kept to
show it lists the same URLs. The Web Reports JSON form is not committed
because it carries each server's token. The `_403` files were captured by
`scripts/capture_fixtures.py --only explorers --only webreports` as a
non-master operator.
