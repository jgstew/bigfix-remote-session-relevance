from __future__ import annotations

from bigfix_remote_session_relevance.redact import redact


def test_session_tokens_are_replaced() -> None:
    text = "<bf:sessionToken>3jPHTrTJSea2o76xiGM4K8fQuSE</bf:sessionToken><sessionToken>x</sessionToken>"
    assert redact(text) == (
        "<bf:sessionToken>REDACTED</bf:sessionToken><sessionToken>REDACTED</sessionToken>"
    )


def test_ipv4_addresses_become_documentation_addresses() -> None:
    assert redact("http://10.20.30.40:52311/x and 10.1.2.3") == (
        "http://192.0.2.1:52311/x and 192.0.2.2"
    )


def test_ipv4_mapping_is_stable_within_one_call() -> None:
    assert redact("10.0.0.1 10.0.0.2 10.0.0.1") == "192.0.2.1 192.0.2.2 192.0.2.1"


def test_explicit_secrets_and_hosts() -> None:
    text = 'user "someoperator" on bigfix.lab.internal with pw hunter2, BIGFIX.LAB.INTERNAL'
    out = redact(
        text,
        hosts=["bigfix.lab.internal"],
        secrets=["hunter2", "someoperator"],
    )
    assert out == 'user "REDACTED" on bigfix.example.com with pw REDACTED, bigfix.example.com'


def test_json_escaped_slashes_are_handled() -> None:
    # The REST API escapes "/" as \u002f in JSON strings.
    text = r'["http:\u002f\u002fbigfix.lab.internal:52311\u002fcgi-bin"]'
    out = redact(text, hosts=["bigfix.lab.internal"])
    assert "lab.internal" not in out
    assert "bigfix.example.com" in out


def test_empty_values_are_ignored() -> None:
    assert redact("abc", hosts=[""], secrets=["", None]) == "abc"  # type: ignore[list-item]
