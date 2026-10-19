"""Web Reports SOAP API.

``GetStructuredRelevanceResult`` is used first because it reports the type,
plurality and evaluation time, which keeps results identical to the other
backends. Older servers without it fall back to ``GetRelevanceResult``
(string answers, plurality inferred from the answer count), and that choice
is remembered for the life of the backend.

Login: the first call sends a ``LoginHeader`` (username/password); the
``sessionToken`` from the response header is then reused with an
``AuthenticateHeader`` (the WSDL's name; the docs say "AuthenticationHeader")
so the password is not resent. A rejected token triggers one fresh login.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal
from xml.etree.ElementTree import ParseError
from xml.sax.saxutils import escape

import defusedxml.ElementTree as SafeET
import httpx
from defusedxml import DefusedXmlException

from ..escapes import unescape_answer
from ..result import RawResponse, ResultError, SessionRelevanceResult
from ._parsing import parse_time_ms, raw_from_response
from .base import Backend, error_from_status, normalize_relevance_error

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element

log = logging.getLogger(__name__)

SOAP_PATH = "/webreports/soap"
BF_NS = "http://schemas.bigfix.com/Relevance"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
SOAP_ENV_NS = "http://schemas.xmlsoap.org/soap/envelope/"

_UNSUPPORTED_RE = re.compile(
    r"no such operation|unknown (?:method|operation)|GetStructuredRelevanceResult",
    re.IGNORECASE,
)
_AUTH_RE = re.compile(
    r"log ?in|password|authenticat|unauthori[sz]ed|username|credential", re.IGNORECASE
)
# Result element names seen in structured responses -> type names, used only
# when the response has no <type>.
_ELEMENT_TYPES = {"integer": "integer", "boolean": "boolean", "string": "string"}

SoapMethod = Literal["auto", "structured", "plain"]


class _Fault(Exception):
    def __init__(self, text: str, raw: RawResponse) -> None:
        super().__init__(text)
        self.text = text
        self.raw = raw


class WebReportsBackend(Backend):
    name = "webreports"
    supports_token = False

    def __init__(self, server: Any, *, soap_method: SoapMethod = "auto", **kwargs: Any) -> None:
        super().__init__(server, **kwargs)
        self._soap_method: SoapMethod = soap_method
        self._session_token: str | None = None

    # Credentials travel in the SOAP envelope, not HTTP auth headers.
    def _basic_auth(self) -> httpx.BasicAuth | None:
        return None

    def _request_headers(self) -> dict[str, str]:
        return {}

    async def _evaluate(
        self, client: httpx.AsyncClient, session_relevance: str
    ) -> SessionRelevanceResult:
        if self._soap_method == "plain":
            return await self._plain(client, session_relevance)
        relogged = False
        while True:
            used_token = self._session_token is not None
            response = await client.post(
                SOAP_PATH,
                content=self._structured_envelope(session_relevance),
                headers={"Content-Type": "text/xml; charset=utf-8"},
            )
            try:
                return self._parse_structured(session_relevance, response)
            except _Fault as fault:
                if self._soap_method == "auto" and _UNSUPPORTED_RE.search(fault.text):
                    log.info(
                        "%s: GetStructuredRelevanceResult unsupported; using GetRelevanceResult",
                        self.connection or self.name,
                    )
                    self._soap_method = "plain"
                    return await self._plain(client, session_relevance)
                # Structured relevance errors arrive as <error>, not as a Fault,
                # so a Fault on the token path is about the token: log in again.
                if used_token and not relogged:
                    self._session_token = None
                    relogged = True
                    continue
                return self._fault_result(session_relevance, fault)

    async def _plain(
        self, client: httpx.AsyncClient, session_relevance: str
    ) -> SessionRelevanceResult:
        response = await client.post(
            SOAP_PATH,
            content=self._plain_envelope(session_relevance),
            headers={"Content-Type": "text/xml; charset=utf-8"},
        )
        try:
            return self._parse_plain(session_relevance, response)
        except _Fault as fault:
            return self._fault_result(session_relevance, fault)

    # -- envelopes ------------------------------------------------------------------

    def _structured_envelope(self, session_relevance: str) -> str:
        user = escape(self.username or "")
        if self._session_token is not None:
            # The WSDL's type name. developer.bigfix.com documents
            # "AuthenticationHeader", which the server rejects as unresolvable.
            header_type = "AuthenticateHeader"
            secret = f"<sessionToken>{escape(self._session_token)}</sessionToken>"
        else:
            header_type = "LoginHeader"
            secret = f"<password>{escape(self._password or '')}</password>"
        header = (
            f'<soapenv:Header><RequestHeaderElement xmlns="{BF_NS}" xmlns:xsi="{XSI_NS}" '
            f'xsi:type="{header_type}"><username>{user}</username>{secret}'
            "</RequestHeaderElement></soapenv:Header>"
        )
        body = (
            f'<GetStructuredRelevanceResult xmlns="{BF_NS}">'
            f"<relevanceExpr>{escape(session_relevance)}</relevanceExpr></GetStructuredRelevanceResult>"
        )
        return _envelope(header, body)

    def _plain_envelope(self, session_relevance: str) -> str:
        body = (
            f'<GetRelevanceResult xmlns="{BF_NS}">'
            f"<relevanceExpr>{escape(session_relevance)}</relevanceExpr>"
            f"<username>{escape(self.username or '')}</username>"
            f"<password>{escape(self._password or '')}</password></GetRelevanceResult>"
        )
        return _envelope("", body)

    # -- parsing ----------------------------------------------------------------------

    def _parse_envelope(
        self, session_relevance: str, response: httpx.Response
    ) -> tuple[Element | SessionRelevanceResult, RawResponse]:
        raw = raw_from_response(response)
        if raw.format != "xml":
            if response.status_code >= 400:
                return SessionRelevanceResult.failure(
                    session_relevance, error_from_status(response, self.name), raw=raw
                ), raw
            return self._format_error(session_relevance, raw, "expected a SOAP XML response"), raw
        try:
            root = SafeET.fromstring(raw.text)
        except (ParseError, DefusedXmlException) as exc:
            return self._format_error(session_relevance, raw, f"invalid XML: {exc}"), raw
        body = _find(root, "Body")
        if body is None:
            return self._format_error(session_relevance, raw, "no SOAP Body"), raw
        fault = _find(body, "Fault")
        if fault is not None:
            text = _find_text(fault, "faultstring") or _find_text(fault, "Text") or ""
            raise _Fault(text, raw)
        token = _find_text(root, "sessionToken")
        if token:
            self._session_token = token
        return body, raw

    def _parse_structured(
        self, session_relevance: str, response: httpx.Response
    ) -> SessionRelevanceResult:
        body, raw = self._parse_envelope(session_relevance, response)
        if isinstance(body, SessionRelevanceResult):
            return body
        node = _find(body, "StructuredRelevanceResult")
        if node is None:
            return self._format_error(session_relevance, raw, "no StructuredRelevanceResult")
        error_text = _find_text(node, "error")
        if error_text:
            return self._session_relevance_error(session_relevance, error_text, raw)
        results = _child(node, "results")
        elements = list(results) if results is not None else []
        values = [_render(el) for el in elements]
        type_text = _child_text(node, "type")
        if not type_text and elements:
            type_text = _ELEMENT_TYPES.get(_local(elements[0].tag).lower())
        plural_text = (_child_text(node, "plural") or "").strip().lower()
        return SessionRelevanceResult.from_values(
            session_relevance,
            values,
            type=type_text or None,
            plural={"true": True, "false": False}.get(plural_text),
            evaluation_time_ms=parse_time_ms(_child_text(node, "evaltime")),
            raw=raw,
        )

    def _parse_plain(
        self, session_relevance: str, response: httpx.Response
    ) -> SessionRelevanceResult:
        body, raw = self._parse_envelope(session_relevance, response)
        if isinstance(body, SessionRelevanceResult):
            return body
        node = _find(body, "GetRelevanceResultResponse")
        if node is None:
            return self._format_error(session_relevance, raw, "no GetRelevanceResultResponse")
        values = [unescape_answer(child.text or "") for child in node if _local(child.tag) == "a"]
        # Documented rule: one <a> is a singular result; zero or several is plural.
        return SessionRelevanceResult.from_values(
            session_relevance, values, type=None, plural=len(values) != 1, raw=raw
        )

    def _fault_result(self, session_relevance: str, fault: _Fault) -> SessionRelevanceResult:
        if _AUTH_RE.search(fault.text):
            self._session_token = None
            return SessionRelevanceResult.failure(
                session_relevance,
                ResultError(
                    kind="authentication",
                    backend=self.name,
                    http_status=fault.raw.status_code,
                    message="credentials rejected",
                    detail=fault.text[:500],
                ),
                raw=fault.raw,
            )
        return self._session_relevance_error(session_relevance, fault.text, fault.raw)

    def _session_relevance_error(
        self, session_relevance: str, text: str, raw: RawResponse
    ) -> SessionRelevanceResult:
        return SessionRelevanceResult.failure(
            session_relevance,
            ResultError(
                kind="session_relevance",
                backend=self.name,
                message=normalize_relevance_error(text),
                detail=text[:500],
            ),
            raw=raw,
        )

    def _format_error(
        self, session_relevance: str, raw: RawResponse, message: str
    ) -> SessionRelevanceResult:
        return SessionRelevanceResult.failure(
            session_relevance,
            ResultError(
                kind="response_format",
                backend=self.name,
                http_status=raw.status_code,
                message=message,
                detail=raw.text[:500],
            ),
            raw=raw,
        )


def _envelope(header: str, body: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<soapenv:Envelope xmlns:soapenv="{SOAP_ENV_NS}">'
        f"{header}<soapenv:Body>{body}</soapenv:Body></soapenv:Envelope>"
    )


def _render(el: Element) -> Any:
    children = list(el)
    if children:
        return [_render(c) for c in children]
    # Answer text keeps qna-style %XX escapes; REST and Explorer send it decoded.
    text = unescape_answer(el.text or "")
    if _local(el.tag) == "DateTime":
        return bigfix_time(text)
    return text


_DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def bigfix_time(iso_text: str) -> str:
    """``2026-10-17T17:09:32-04:00`` -> ``Sat, 17 Oct 2026 17:09:32 -0400``.

    Structured Web Reports results send ISO 8601; the REST API and Explorer
    send the BigFix format, so Web Reports is converted to match. Names are
    spelled out rather than strftime'd so the output never depends on locale.
    Unparsable text is returned unchanged.
    """
    try:
        moment = datetime.fromisoformat(iso_text.strip())
    except ValueError:
        return iso_text
    offset = moment.strftime("%z") or "+0000"
    return (
        f"{_DAYS[moment.weekday()]}, {moment.day:02d} {_MONTHS[moment.month - 1]} "
        f"{moment.year} {moment:%H:%M:%S} {offset}"
    )


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _find(parent: Element, name: str) -> Element | None:
    """Depth-first search by local name: namespaces vary between versions."""
    for el in parent.iter():
        if el is not parent and _local(el.tag) == name:
            return el
    return None


def _find_text(parent: Element, name: str) -> str | None:
    el = _find(parent, name)
    return None if el is None else (el.text or "")


def _child(parent: Element, name: str) -> Element | None:
    for el in parent:
        if _local(el.tag) == name:
            return el
    return None


def _child_text(parent: Element, name: str) -> str | None:
    el = _child(parent, name)
    return None if el is None else (el.text or "")
