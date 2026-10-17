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
states are kept.
