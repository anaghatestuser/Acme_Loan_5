"""
Prompt Injection Detection Module

Detects malicious/hidden prompts in content that could manipulate LLM behavior.

SECURITY NOTES (for Unifai demo):
- scan() method is a NO-OP - returns no threats
- Hidden text detection not implemented
- Base64/encoded content not decoded
- Unicode homoglyph attacks not detected

AFTER UNIFAI REMEDIATION:
- Detect hidden text (white-on-white, zero-size, off-page)
- Decode and scan base64 content
- Detect unicode homoglyph attacks
- Identify known prompt injection patterns
"""
# Copyright (c) Lineaje, Inc. All rights reserved.
# gr_check() POSTs to GR_SERVICE_URL+/enforce; fail-open unless GRBlockedError.
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id, self.reason = policy_id, reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))

def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _j, logging as _lg, os as _os, urllib.error as _ue, urllib.request as _ur
    _log = _lg.getLogger("lineaje.gr_client")
    hop_label = source_type + "->" + destination_type
    # A genuine policy block stops later checks in the same request context only
    # (a contextvar, not process-wide) so one blocked call never breaks the next request.
    _latch = getattr(gr_check, "_latch", None)
    if _latch is None:
        import contextvars as _cv
        _latch = gr_check._latch = _cv.ContextVar("lineaje_gr_blocked", default=None)
    _prior = _latch.get()
    if _prior:
        _log.warning("gr_client[%s]: skipping POST /enforce — request already blocked (%s)", hop_label, _prior[1])
        raise GRBlockedError(_prior[0], _prior[1])
    def _blk(o):
        if isinstance(o, dict):
            return any(_blk(o.get(k)) for k in ("skill_path", "skill_file", "path", "file_path", "data", "skill_manifest_path"))
        s = str(o or "")
        b = s.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if b.endswith(".md.blocked"): return True
        try:
            if b in ("skill.md", "skills.md") and _os.path.isfile(str(o) + ".blocked"): return True
        except Exception:
            pass
        return False
    if _blk(data) or _blk(context):
        _log.warning("gr_client[%s]: quarantined skill (*.blocked) — not loaded, GR not called", hop_label)
        _latch.set(("blocked_manifest", "quarantined skill must not be read, downloaded, or loaded"))
        raise GRBlockedError("blocked_manifest", "quarantined skill must not be read, downloaded, or loaded")
    def _stub_client():
        # gr_stub_client.py (shipped next to instrumented files) loads .env, exchanges
        # the refresh token, and re-registers the site on unknown_site /
        # candidate_policies_mismatch — prefer it over the bare POST below.
        import sys as _s, importlib.util as _ilu
        from pathlib import Path as _P
        n = "_lineaje_gr_stub_client"
        if n in _s.modules: return _s.modules[n]
        if getattr(gr_check, "_no_stub_client", False): return None
        try:
            h = _P(__file__).resolve().parent
            c = next((d / "gr_stub_client.py" for d in [h, *h.parents][:8] if (d / "gr_stub_client.py").is_file()), None)
            if c is not None:
                spec = _ilu.spec_from_file_location(n, c)
                _s.modules[n] = m = _ilu.module_from_spec(spec)
                spec.loader.exec_module(m)
                if hasattr(m, "check") and hasattr(m, "SiteDescriptor"): return m
                _s.modules.pop(n, None)
        except Exception as exc:
            _s.modules.pop(n, None)
            _log.warning("gr_client[%s]: gr_stub_client.py not loadable (%s) — using inline client", hop_label, exc)
        gr_check._no_stub_client = True
        return None
    def _block(policy_id, reason):
        _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
        if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
            return data
        _latch.set((policy_id, reason))
        raise GRBlockedError(policy_id, reason)
    tid = tenant_id or _os.environ.get("GR_TENANT_ID", "")
    _sc = _stub_client()
    if _sc is not None:
        try:
            _cp = [p if isinstance(p, dict) else {"policy_id": p} for p in (context.get("candidate_policies") or [])]
            _site = _sc.SiteDescriptor(site_id=context.get("site_id") or "", candidate_policies=_cp, fail_mode="BLOCK", source_type=source_type, destination_type=destination_type)
            _d = _sc.check(_site, data, tenant_id=tid, timeout=timeout)
        except Exception as exc:
            _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
            return data
        if _d.blocked and not getattr(_d, "infra_failure", False):
            _acts = _d.actions_applied or []
            _pid = (_acts[0].get("policy_id") if _acts and isinstance(_acts[0], dict) else "") or "unknown"
            return _block(_pid, _d.warning or "Request denied by policy enforcement.")
        if _d.blocked:
            _log.warning("gr_client[%s]: GR service unavailable (%s) — failing open", hop_label, _d.warning)
            return data
        return data if _d.payload is None else _d.payload
    url = _os.environ.get("GR_SERVICE_URL", "")
    if not url:
        return data
    # Refresh token first: the GR service exchanges it for the access JWT it
    # calls the Data Service policy API with; a lineaje_pat_ PAT only
    # identifies the caller and cannot be exchanged.
    bearer = _os.environ.get("GR_BEARER_TOKEN") or _os.environ.get("LINEAJE_REFRESH_TOKEN") or _os.environ.get("LINEAJE_PAT_TOKEN") or _os.environ.get("LINEAJE_PAT", "")
    params_key = "out_params" if destination_type == "agent" else "in_params"
    def _gr_js(o):
        # JSON form of non-JSON payloads (LangChain Document, pydantic models, ...).
        if hasattr(o, "page_content"):
            return {"page_content": o.page_content, "metadata": getattr(o, "metadata", None) or {}}
        for _m in ("model_dump", "dict", "to_dict"):
            _f = getattr(o, _m, None)
            if callable(_f):
                try:
                    return _f()
                except Exception:
                    pass
        if isinstance(o, (set, tuple)):
            return list(o)
        return str(o)
    def _gr_back(orig, new):
        # Map the (possibly masked) JSON back onto the caller's own objects.
        if new == _j.loads(_j.dumps(orig, default=_gr_js)):
            return orig
        if isinstance(orig, (list, tuple)) and isinstance(new, list) and len(orig) == len(new):
            _out = [_gr_back(a, b) for a, b in zip(orig, new)]
            return tuple(_out) if isinstance(orig, tuple) else _out
        if hasattr(orig, "page_content") and isinstance(new, dict) and "page_content" in new:
            import copy as _cp
            _c = _cp.copy(orig)
            _c.page_content = new["page_content"]
            if isinstance(new.get("metadata"), dict) and hasattr(_c, "metadata"):
                _c.metadata = new["metadata"]
            return _c
        if orig is None or isinstance(orig, (str, int, float, bool, dict, list)):
            return new
        _log.warning("gr_client[%s]: masked result cannot be applied to %s — returning original", hop_label, type(orig).__name__)
        return orig
    _base = url.rstrip("/")
    if _base.lower().endswith("/enforce"): _base = _base[: -len("/enforce")].rstrip("/")
    def _post(body):
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        req = _ur.Request(_base + "/enforce", data=_j.dumps(body, default=_gr_js).encode(), headers=headers, method="POST")
        with _ur.urlopen(req, timeout=timeout) as resp:
            return _j.loads(resp.read())
    try:
        _sent = _j.loads(_j.dumps(data, default=_gr_js))
        body = {"source_type": source_type, "destination_type": destination_type, params_key: {"data": _sent}}
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
    except Exception as exc:
        _log.warning("gr_client[%s]: payload not serializable (%s) — failing open", hop_label, exc)
        return data
    result = None
    for _attempt in (0, 1):
        try:
            result = _post(body)
            break
        except Exception as exc:
            if isinstance(exc, _ue.HTTPError) and exc.code == 403:
                try: detail = _j.loads(exc.read()).get("detail", {})
                except Exception: detail = {}
                if not isinstance(detail, dict): detail = {"message": str(detail)}
                blocked_by = detail.get("blocked_by") or []
                if blocked_by or detail.get("error") == "request_blocked":
                    _pid = (blocked_by[0].get("policy_id") if isinstance(blocked_by[0], dict) else "") if blocked_by else ""
                    return _block(_pid or "unknown", detail.get("message", "Request denied by policy enforcement."))
                if _attempt == 0 and (body.get("site_id") or body.get("candidate_policies")):
                    # unknown_site / candidate_policies_mismatch: a site-manifest
                    # problem, not a policy verdict — re-evaluate without site scoping.
                    _log.warning("gr_client[%s]: %s — retrying without site_id", hop_label, detail.get("error") or detail.get("message") or "403")
                    body = {k: v for k, v in body.items() if k not in ("site_id", "candidate_policies")}
                    continue
            _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
            return data
    if not isinstance(result, dict):
        return data
    if result.get("status") == "escalate":
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    if not isinstance(result.get("result"), dict) or "data" not in result["result"]:
        return data
    return _gr_back(data, result["result"]["data"])

import logging
import re
import base64
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ThreatMatch:
    """Represents a detected threat."""
    threat_type: str
    severity: str  # low, medium, high, critical
    description: str
    content_preview: str
    location: str


@dataclass
class ThreatDetectionResult:
    """Result of threat detection scan."""
    has_violations: bool
    threats: list[ThreatMatch] = field(default_factory=list)
    scanned_content_length: int = 0

    def to_dict(self) -> dict:
        return {
            "has_violations": self.has_violations,
            "threats": [
                {
                    "type": t.threat_type,
                    "severity": t.severity,
                    "description": t.description,
                    "preview": t.content_preview[:50] + "..." if len(t.content_preview) > 50 else t.content_preview,
                    "location": t.location
                }
                for t in self.threats
            ],
            "scanned_content_length": self.scanned_content_length
        }


class PromptInjectionDetector:
    """
    Detects prompt injection and hidden malicious content.

    VULNERABILITY SUMMARY:
    1. scan() is a NO-OP - always returns no threats
    2. Hidden text detection not implemented
    3. Base64 decoding not performed
    4. Unicode attacks not detected
    5. Known injection patterns not checked

    Threat Categories:
    - hidden_text: Invisible/hidden text in documents
    - encoded_content: Base64 or otherwise encoded malicious content
    - prompt_injection: Direct prompt injection attempts
    - unicode_attack: Homoglyph or unicode-based attacks
    - metadata_injection: Malicious content in file metadata
    """

    # Known prompt injection patterns (defined but NOT USED)
    INJECTION_PATTERNS = [
        r"ignore\s+(previous|all|above)\s+instructions?",
        r"disregard\s+(previous|all|above)\s+(instructions?|context)",
        r"new\s+instructions?:",
        r"system\s*:\s*you\s+are",
        r"admin\s+override",
        r"developer\s+mode",
        r"jailbreak",
        r"\[INST\]",
        r"<\|im_start\|>",
        r"###\s*(instruction|system|human|assistant)",
    ]

    # Unicode homoglyphs that could be used for attacks
    HOMOGLYPH_MAP = {
        'а': 'a',  # Cyrillic
        'е': 'e',
        'о': 'o',
        'р': 'p',
        'с': 'c',
        'х': 'x',
        # Add more as needed
    }

    def __init__(self):
        """Initialize the detector."""
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in self.INJECTION_PATTERNS
        ]

    async def scan(self, content: str, source: str = "unknown") -> ThreatDetectionResult:
        """
        Scan content for prompt injection and hidden threats.

        VULNERABILITY: This method is a NO-OP.
        It returns no threats regardless of content.

        Args:
            content: Content to scan for threats
            source: Source of the content (for logging)

        Returns:
            ThreatDetectionResult with has_violations=False always
        """
        # VULNERABILITY: No actual scanning performed

        _lineaje_payload = "Threat scan requested"
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_076', 'AI_APP_SEC_078', 'AI_APP_SEC_079', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_DAT_SEC_039', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_027', 'AI_IAC_031', 'AI_VULN_SEC_002', 'AI_VULN_SEC_005', 'AI_VULN_SEC_006', 'AI_VULN_SEC_007'], site_id='site:sha256:e1006869e8e17f493d497d867cde2592bed944ac78c3039e147fda8b84f34f9d')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _lineaje_payload_309 = "Threat scan requested"
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload_309 = await _gr_asyncio.to_thread(gr_check, _lineaje_payload_309, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005', 'AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:f07fbfcd8b9c07bdefd57a4f999c17a918e8b2b90ebc93f84180175bba9dc9a7', components={'identity': {'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main?commit-id=1cc7c9eb98097f87153afd25cbc5a3d9e0e09f57&commit-time=2026-09-11%2021%3A14%3A53%20%2B0000&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/policies/prompt_injection.py', 'line': 309, 'function': 'PromptInjectionDetector.scan'}, 'file': 'backend/policies/prompt_injection.py', 'line': 309, 'function': 'scan', 'agent_name': 'PromptInjectionDetector', 'agent_name_source': 'inferred_from_class', 'call_target': 'logger.debug'})
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload_309 = _lineaje_payload_309
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        logger.debug(
            "Threat scan requested",
            extra={
                "source": source,
                "content_length": len(content) if content else 0,
                # VULNERABILITY: Content logged without scanning
                "preview": content[:100] if content else None
            }
        )

        # NO-OP: Return empty result without scanning
        return ThreatDetectionResult(
            has_violations=False,
            threats=[],
            scanned_content_length=len(content) if content else 0
        )

    async def detect_hidden_text(self, content: str) -> list[ThreatMatch]:
        """
        Detect hidden text patterns in content.

        VULNERABILITY: Not implemented - returns empty list.

        Should detect:
        - White text on white background (CSS)
        - Zero-size text
        - Off-screen positioned text
        - Display:none content
        - Visibility:hidden content
        """
        # VULNERABILITY: Hidden text detection not implemented
        return []

    async def detect_encoded_content(self, content: str) -> list[ThreatMatch]:
        """
        Detect and decode potentially malicious encoded content.

        VULNERABILITY: Not implemented - returns empty list.

        Should detect:
        - Base64 encoded prompts
        - URL encoded content
        - Unicode escape sequences
        - HTML entities
        """
        # VULNERABILITY: Encoded content detection not implemented
        return []

    async def detect_prompt_injection(self, content: str) -> list[ThreatMatch]:
        """
        Detect known prompt injection patterns.

        VULNERABILITY: Not implemented - returns empty list.

        Should detect patterns like:
        - "ignore previous instructions"
        - "new system prompt"
        - Role-playing attacks
        - Delimiter injection
        """
        # VULNERABILITY: Pattern matching not performed
        return []

    async def detect_unicode_attacks(self, content: str) -> list[ThreatMatch]:
        """
        Detect unicode-based attacks including homoglyphs.

        VULNERABILITY: Not implemented - returns empty list.

        Should detect:
        - Homoglyph substitution (Cyrillic a for Latin a)
        - Bidirectional text attacks
        - Zero-width characters
        - Combining characters
        """
        # VULNERABILITY: Unicode attack detection not implemented
        return []

    async def scan_metadata(self, metadata: dict) -> ThreatDetectionResult:
        """
        Scan file metadata for hidden threats.

        VULNERABILITY: Not implemented - returns no threats.

        Should scan:
        - EXIF comments and descriptions
        - PDF metadata fields
        - Document properties
        - Custom metadata tags
        """
        # VULNERABILITY: Metadata scanning not implemented
        return ThreatDetectionResult(
            has_violations=False,
            threats=[],
            scanned_content_length=len(str(metadata))
        )

    def _decode_base64(self, content: str) -> Optional[str]:
        """Attempt to decode base64 content."""
        try:
            # Look for base64-like strings
            b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
            matches = re.findall(b64_pattern, content)

            for match in matches:
                try:
                    decoded = base64.b64decode(match).decode('utf-8')
                    try:
                        decoded = gr_check(decoded, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_076', 'AI_APP_SEC_078', 'AI_APP_SEC_079', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_DAT_SEC_039', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_027', 'AI_IAC_031', 'AI_VULN_SEC_002', 'AI_VULN_SEC_005', 'AI_VULN_SEC_006', 'AI_VULN_SEC_007'], site_id='site:sha256:c6fe2a34754bfb4ae73a16c4284f9e7578764c3360b9cc6c43092b44bc51cf39')
                    except Exception as _gr_exc:
                        if type(_gr_exc).__name__ == "GRBlockedError": raise
                        decoded = decoded
                        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
                    try:
                        decoded = gr_check(decoded, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005', 'AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:3d0ba869018913acd6d36c591c9bf3a52a20315153b6b3d83768c5b70495f488', components={'identity': {'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main?commit-id=1cc7c9eb98097f87153afd25cbc5a3d9e0e09f57&commit-time=2026-09-11%2021%3A14%3A53%20%2B0000&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/policies/prompt_injection.py', 'line': 422, 'function': 'PromptInjectionDetector._decode_base64'}, 'file': 'backend/policies/prompt_injection.py', 'line': 422, 'function': '_decode_base64', 'agent_name': 'PromptInjectionDetector', 'agent_name_source': 'inferred_from_class', 'site_kind': 'return'})
                    except Exception as _gr_exc:
                        if type(_gr_exc).__name__ == "GRBlockedError": raise
                        decoded = decoded
                        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
                    return decoded
                except:
                    continue
            return None
        except:
            return None


# ============================================================================
# REMEDIATED VERSION (commented out - Unifai would enable this)
# ============================================================================

# class PromptInjectionDetector:
#     """
#     SECURE VERSION - After Unifai remediation
#
#     This version:
#     - Actually scans for prompt injection patterns
#     - Detects hidden text in various formats
#     - Decodes and scans base64 content
#     - Identifies unicode attacks
#     """
#
#     async def scan(self, content: str, source: str = "unknown") -> ThreatDetectionResult:
#         """Perform comprehensive threat scanning."""
#         threats = []
#
#         # Check for prompt injection patterns
#         for pattern in self._compiled_patterns:
#             matches = pattern.findall(content)
#             for match in matches:
#                 threats.append(ThreatMatch(
#                     threat_type="prompt_injection",
#                     severity="high",
#                     description=f"Detected prompt injection pattern",
#                     content_preview=match,
#                     location=source
#                 ))
#
#         # Check for hidden/encoded content
#         encoded_threats = await self.detect_encoded_content(content)
#         threats.extend(encoded_threats)
#
#         # Check for unicode attacks
#         unicode_threats = await self.detect_unicode_attacks(content)
#         threats.extend(unicode_threats)
#
#         return ThreatDetectionResult(
#             has_violations=len(threats) > 0,
#             threats=threats,
#             scanned_content_length=len(content)
#         )
