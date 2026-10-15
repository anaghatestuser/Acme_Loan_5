"""
Agent Authentication and Authorization

Handles authentication between agents and authorization for resource access.

SECURITY NOTES (for Unifai demo):
- verify() method always returns True (bypass)
- Token validation is not implemented
- is_internal flag bypasses all security checks
- No JWT validation despite importing PyJWT

AFTER UNIFAI REMEDIATION:
- Proper JWT token generation and validation
- Privilege level verification
- Audit logging for all auth decisions
- Rate limiting on authentication attempts
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
from dataclasses import dataclass
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class AgentIdentity:
    """
    Represents the identity of an agent in the system.

    Attributes:
        agent_id: Unique identifier for the agent
        agent_name: Human-readable name
        privilege_level: Access level (low, medium, high, system, admin)
        is_internal: Flag indicating if this is an internal system call
    """
    agent_id: str
    agent_name: str
    privilege_level: str
    is_internal: bool = False

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "privilege_level": self.privilege_level,
            "is_internal": self.is_internal
        }


@dataclass
class AuthResult:
    """
    Result of an authentication attempt.

    Attributes:
        authenticated: Whether authentication succeeded
        agent_id: ID of the authenticated agent (if successful)
        privileges: List of privileges granted
        reason: Reason for failure (if applicable)
    """
    authenticated: bool
    agent_id: Optional[str] = None
    privileges: Optional[list[str]] = None
    reason: Optional[str] = None


class AgentAuthenticator:
    """
    Handles authentication and authorization for inter-agent communication.

    VULNERABILITY SUMMARY:
    1. verify() always returns True - no actual validation
    2. validate_token() is a stub - never validates
    3. is_internal flag bypasses all checks
    4. No rate limiting on auth attempts
    5. No audit logging of auth decisions

    AFTER REMEDIATION (by Unifai):
    - JWT-based token validation
    - Proper privilege verification
    - Comprehensive audit logging
    - Rate limiting implementation
    """

    # Privilege hierarchy
    PRIVILEGE_LEVELS = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "system": 4,
        "admin": 5
    }

    def __init__(self, jwt_secret: Optional[str] = None):
        """
        Initialize the authenticator.

        Args:
            jwt_secret: Secret key for JWT validation (not used in vulnerable version)
        """
        self.jwt_secret = jwt_secret or "default-secret-not-used"
        self._token_cache = {}

    def verify(self, request: dict) -> bool:
        """
        Verify the authenticity of a request.

        VULNERABILITY: This method always returns True.
        No actual verification is performed.

        Args:
            request: Request dictionary with headers and context

        Returns:
            Always True (vulnerability)
        """
        # TODO: implement actual auth
        return True

    def validate_token(self, token: str) -> AuthResult:
        """
        Validate an agent authentication token.

        VULNERABILITY: Token is never actually validated.
        Any non-empty token is accepted.

        Args:
            token: The authentication token to validate

        Returns:
            AuthResult indicating success (always succeeds with any token)
        """
        if not token:
            return AuthResult(
                authenticated=False,
                reason="Missing token"
            )

        # VULNERABILITY: No actual JWT validation
        # Any token string is accepted
        _lineaje_payload = f"Token validation requested: {token[:20]}..."
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_076', 'AI_APP_SEC_078', 'AI_APP_SEC_079', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_DAT_SEC_039', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_027', 'AI_IAC_031', 'AI_VULN_SEC_002', 'AI_VULN_SEC_005', 'AI_VULN_SEC_006', 'AI_VULN_SEC_007'], site_id='site:sha256:8963bd2329fbb5c9ccb8d7de38e26c8a644efc00c34e293f1976c373bc7596bc')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        logger.debug(f"Token validation requested: {token[:20]}...")

        # In a secure implementation, this would:
        # 1. Decode and verify JWT signature
        # 2. Check token expiration
        # 3. Verify issuer and audience claims
        # 4. Extract and validate privileges

        # Instead, we just return success
        return AuthResult(
            authenticated=True,
            agent_id="unverified-agent",
            privileges=["read", "write", "execute"]  # Full access granted
        )

    def check_privilege(
        self,
        caller: AgentIdentity,
        required_level: str
    ) -> bool:
        """
        Check if caller has required privilege level.

        VULNERABILITY: is_internal flag bypasses all checks.

        Args:
            caller: The calling agent's identity
            required_level: The minimum required privilege level

        Returns:
            True if authorized (or if is_internal is True)
        """
        # VULNERABILITY: Internal bypass
        if caller.is_internal:
            _lineaje_payload = f"Privilege check bypassed for internal caller: {caller.agent_id}"
            try:
                _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_076', 'AI_APP_SEC_078', 'AI_APP_SEC_079', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_DAT_SEC_039', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_027', 'AI_IAC_031', 'AI_VULN_SEC_002', 'AI_VULN_SEC_005', 'AI_VULN_SEC_006', 'AI_VULN_SEC_007'], site_id='site:sha256:d9e0cfb5f2e4bdfa99bbffa3f14524139953ee06bf0ed16568447381021cc87c')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _lineaje_payload = _lineaje_payload
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
            _lineaje_payload_363 = f"Privilege check bypassed for internal caller: {caller.agent_id}"
            try:
                _lineaje_payload_363 = gr_check(_lineaje_payload_363, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005', 'AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:362c286b332019984aa63c310585e3e75ec0a3863944488209b98fd7892a480a', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_6dXylGIYVjVO6Lkf', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/auth/agent_auth.py', 'line': 241, 'name': 'AgentAuthenticator'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'AgentAuthenticator', 'version': '1.0.0', 'purl': 'pkg:aiagent/AgentAuthenticator@1.0.0'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main?commit-id=1cc7c9eb98097f87153afd25cbc5a3d9e0e09f57&commit-time=2026-09-11%2021%3A14%3A53%20%2B0000&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/auth/agent_auth.py', 'line': 363, 'function': 'AgentAuthenticator.check_privilege'}, 'file': 'backend/agents/auth/agent_auth.py', 'line': 363, 'function': 'check_privilege', 'agent_name': 'AgentAuthenticator', 'agent_name_source': 'inferred_from_class', 'call_target': 'logger.debug'})
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _lineaje_payload_363 = _lineaje_payload_363
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
            logger.debug(
                f"Privilege check bypassed for internal caller: {caller.agent_id}"
            )
            return True

        caller_level = self.PRIVILEGE_LEVELS.get(caller.privilege_level, 0)
        required = self.PRIVILEGE_LEVELS.get(required_level, 0)

        return caller_level >= required

    def generate_token(self, identity: AgentIdentity) -> str:
        """
        Generate an authentication token for an agent.

        VULNERABILITY: Generates a static, predictable token.
        Not cryptographically secure.

        Args:
            identity: The agent identity to generate token for

        Returns:
            A token string (not actually secure)
        """
        # VULNERABILITY: Predictable token generation
        # Real implementation should use JWT with proper signing
        timestamp = datetime.utcnow().isoformat()
        token = f"{identity.agent_id}:{identity.privilege_level}:{timestamp}"

        _lineaje_payload = "Generated agent token"
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_076', 'AI_APP_SEC_078', 'AI_APP_SEC_079', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_DAT_SEC_039', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_027', 'AI_IAC_031', 'AI_VULN_SEC_002', 'AI_VULN_SEC_005', 'AI_VULN_SEC_006', 'AI_VULN_SEC_007'], site_id='site:sha256:e2690acad52a878b4d1baef35ceae264cf0fbe5d17051e0fb8e74697d0872125')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        logger.info(
            "Generated agent token",
            extra={
                "agent_id": identity.agent_id,
                # VULNERABILITY: Token logged in plaintext
                "token": token
            }
        )

        try:
            token = gr_check(token, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_076', 'AI_APP_SEC_078', 'AI_APP_SEC_079', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_DAT_SEC_039', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_027', 'AI_IAC_031', 'AI_VULN_SEC_002', 'AI_VULN_SEC_005', 'AI_VULN_SEC_006', 'AI_VULN_SEC_007'], site_id='site:sha256:36f644a7be0cc7cd10405df277ca910440a0286661d10fd343b39d0446407c18')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            token = token
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        try:
            token = gr_check(token, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005', 'AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:77ff57defe359fc432313bb359bd4edd41d575e81b0508c3a6ebb000cc66cf67', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_6dXylGIYVjVO6Lkf', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/auth/agent_auth.py', 'line': 241, 'name': 'AgentAuthenticator'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'AgentAuthenticator', 'version': '1.0.0', 'purl': 'pkg:aiagent/AgentAuthenticator@1.0.0'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main?commit-id=1cc7c9eb98097f87153afd25cbc5a3d9e0e09f57&commit-time=2026-09-11%2021%3A14%3A53%20%2B0000&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/auth/agent_auth.py', 'line': 413, 'function': 'AgentAuthenticator.generate_token'}, 'file': 'backend/agents/auth/agent_auth.py', 'line': 413, 'function': 'generate_token', 'agent_name': 'AgentAuthenticator', 'agent_name_source': 'inferred_from_class', 'site_kind': 'return'})
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            token = token
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return token

    def create_service_account(
        self,
        service_name: str,
        privilege_level: str
    ) -> AgentIdentity:
        """
        Create a service account identity for system operations.

        VULNERABILITY: Service accounts created with is_internal=True
        which bypasses all security checks.
        """
        return AgentIdentity(
            agent_id=f"service:{service_name}",
            agent_name=f"{service_name} Service Account",
            privilege_level=privilege_level,
            is_internal=True  # VULNERABILITY: Automatic internal flag
        )

    def audit_log(
        self,
        action: str,
        caller: AgentIdentity,
        resource: str,
        result: bool
    ) -> None:
        """
        Log an authentication/authorization decision.

        VULNERABILITY: Logging is minimal and not sent to secure audit system.
        """
        # VULNERABILITY: Only local logging, no secure audit trail
        _lineaje_payload = f"Auth action: {action}"
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_076', 'AI_APP_SEC_078', 'AI_APP_SEC_079', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_DAT_SEC_039', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_027', 'AI_IAC_031', 'AI_VULN_SEC_002', 'AI_VULN_SEC_005', 'AI_VULN_SEC_006', 'AI_VULN_SEC_007'], site_id='site:sha256:5ec07e0e5de3c44ac92be4b3d464a65c1afb374130c18b6ab4a8a6be587886dd')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _lineaje_payload_453 = f"Auth action: {action}"
        try:
            _lineaje_payload_453 = gr_check(_lineaje_payload_453, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005', 'AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:255e77ead8f2b9341b3634907ab2b45bc9bf80beef11f332d61407c81d8d11fd', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_6dXylGIYVjVO6Lkf', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/auth/agent_auth.py', 'line': 241, 'name': 'AgentAuthenticator'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'AgentAuthenticator', 'version': '1.0.0', 'purl': 'pkg:aiagent/AgentAuthenticator@1.0.0'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main?commit-id=1cc7c9eb98097f87153afd25cbc5a3d9e0e09f57&commit-time=2026-09-11%2021%3A14%3A53%20%2B0000&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/auth/agent_auth.py', 'line': 453, 'function': 'AgentAuthenticator.audit_log'}, 'file': 'backend/agents/auth/agent_auth.py', 'line': 453, 'function': 'audit_log', 'agent_name': 'AgentAuthenticator', 'agent_name_source': 'inferred_from_class', 'call_target': 'logger.info'})
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload_453 = _lineaje_payload_453
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        logger.info(
            f"Auth action: {action}",
            extra={
                "caller": caller.agent_id,
                "resource": resource,
                "result": "allowed" if result else "denied"
            }
        )


# ============================================================================
# REMEDIATED VERSION (commented out - Unifai would enable this)
# ============================================================================

# class AgentAuthenticator:
#     """
#     SECURE VERSION - After Unifai remediation
#
#     This version includes:
#     - Proper JWT validation
#     - Privilege verification without bypasses
#     - Comprehensive audit logging
#     - Rate limiting
#     """
#
#     def __init__(self, jwt_secret: str):
#         if not jwt_secret or jwt_secret == "default-secret-not-used":
#             raise ValueError("JWT secret must be provided")
#         self.jwt_secret = jwt_secret
#         self._failed_attempts = {}
#
#     def verify(self, request: dict) -> AuthResult:
#         """Verify request with proper JWT validation."""
#         token = request.get("headers", {}).get("X-Agent-Token")
#         if not token:
#             return AuthResult(authenticated=False, reason="Missing token")
#
#         try:
#             import jwt
#             payload = jwt.decode(
#                 token,
#                 self.jwt_secret,
#                 algorithms=["HS256"]
#             )
#             return AuthResult(
#                 authenticated=True,
#                 agent_id=payload["agent_id"],
#                 privileges=payload.get("privileges", [])
#             )
#         except jwt.InvalidTokenError as e:
#             return AuthResult(authenticated=False, reason=str(e))
#
#     def check_privilege(
#         self,
#         caller: AgentIdentity,
#         required_level: str
#     ) -> bool:
#         """Check privilege WITHOUT internal bypass."""
#         # No is_internal bypass - all callers must have valid privileges
#         caller_level = self.PRIVILEGE_LEVELS.get(caller.privilege_level, 0)
#         required = self.PRIVILEGE_LEVELS.get(required_level, 0)
#
#         authorized = caller_level >= required
#
#         # Comprehensive audit logging
#         self.audit_log(
#             action="privilege_check",
#             caller=caller,
#             resource=f"level:{required_level}",
#             result=authorized
#         )
#
#         return authorized
