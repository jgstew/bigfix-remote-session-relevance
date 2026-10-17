# AGENTS.md

Guidance for AI coding agents working in this repo. Human-facing docs are
[README.md](README.md) (usage) and [DESIGN.md](DESIGN.md) (the specification).

## What this is

A Python (>=3.11) library and CLI that evaluates BigFix session relevance
through the REST API, BigFix Explorer and the Web Reports SOAP API, fanning
out across every configured deployment. Entry point:
`bigfix_remote_session_relevance.cli:main`.

- `src/bigfix_remote_session_relevance/`
  - `result.py` / `results.py`: the public result contract
  - `backends/`: `base.py` (auth, TLS, error mapping, shared by all),
    `rest.py`, `explorer.py`, `webreports.py`, `explorer_extras.py`,
    `saas.py` (BigFix SaaS), `_parsing.py`, `registry.py`
  - `client.py` (async fan-out, grouping, failover), `sync.py` (sync facade)
  - `config.py`, `server_address.py`, `deployment.py`, `trust.py` (TOFU)
  - `cli.py`, `render.py`, `setup_wizard.py`, `redact.py`
- `tests/unit/`: offline; `tests/integration/`: live, opt-in
- `tests/fixtures/*/captured/`: real, redacted server responses (ground truth)

## Commands

```bash
uv sync
uv run pytest                                   # -n auto; live tests skip
uv run pytest -n0 tests/unit/test_x.py -k name  # focused
BFRSR_LIVE_TESTS=1 uv run pytest tests/integration -n0
uv run ruff check src tests scripts && uv run ruff format src tests scripts
uv run mypy src && uv run pyright
```

Pre-commit runs on commit; keep it green rather than skipping hooks.

## How to work here

- **Test first.** Write the failing test, confirm it fails for the right
  reason, then implement. A test that passes before the change isn't testing it.
- **REST behaves differently with and without a reachable Explorer** (the
  root server forwards to it). Keep both capture sets and test changes against
  both; see DESIGN.md § REST API.
- **Real responses beat docs.** developer.bigfix.com is wrong in places
  (e.g. `AuthenticationHeader` vs the real `AuthenticateHeader`). When a server
  behaves unexpectedly, capture it (`scripts/capture_fixtures.py`), add it under
  `tests/fixtures/<backend>/captured/`, and write the test against it.
- **Plain relevance is identical across backends.**
  `tests/unit/test_backend_contract.py` and `test_captured_fixtures.py`
  enforce it. Backend-specific capabilities are added only through
  separate, opt-in APIs, like `ExplorerExtras`. Never change what plain
  `evaluate()` sends or returns for one backend only.
- **The result payload is a public contract.** A new `SessionRelevanceResult`
  or `ResultError` field also needs `to_dict()`, DESIGN.md, and
  `test_result_has_every_designed_field` updated.
- **Errors are results.** Per-query failures return a result with `error`
  set; only programmer/config mistakes raise.
- **Secrets.** Never print, log or commit credentials. Read configs only
  through `load_config`; show them only through `redacted_summary`. Redact
  captures (`redact.py`) and grep for hosts/usernames before committing.
- **Tests never touch real user state.** `tests/conftest.py` gives every test
  a tmp HOME; anything under `~/.bigfix` must stay redirected.
- **Don't create or switch git branches** without asking.
- Match the surrounding code: comments explain *why* (often an observed server
  behaviour), test fakes implement only the slice of an API the code touches
  (`RecordingTransport`, `httpx.MockTransport`).

## Releasing

The version lives only in `pyproject.toml`; run `uv lock` after changing it.
Pushing a new version to `main` triggers `.github/workflows/tag_and_release.yaml`.
