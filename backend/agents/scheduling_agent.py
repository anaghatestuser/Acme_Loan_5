"""Scheduling Agent class with explicit model invocation."""
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
    _obs = bool(context.get("observe_only"))  # a log-only call never enforces, so a block neither skips nor sets it
    _prior = None if _obs else _latch.get()
    if _prior:
        _log.warning("gr_client[%s]: skipping POST /enforce — request already blocked (%s)", hop_label, _prior[1])
        try:  # still tell the Guardrail the activity happened (no data, no policy)
            import sys as _s
            _m = _s.modules.get("_lineaje_gr_stub_client")
            if _m is not None and hasattr(_m, "_report_skipped_after_block"):
                _f = getattr(_m.SiteDescriptor, "__dataclass_fields__", {})
                _m._report_skipped_after_block(_m.SiteDescriptor(site_id=context.get("site_id") or "", source_type=source_type, destination_type=destination_type, **{k: context[k] for k in ("components", "interaction_id") if context.get(k) and k in _f}), tenant_id or _os.environ.get("GR_TENANT_ID", ""))
        except Exception:
            pass
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
        if not _obs: _latch.set((policy_id, reason))
        raise GRBlockedError(policy_id, reason)
    tid = tenant_id or _os.environ.get("GR_TENANT_ID", "")
    _sc = _stub_client()
    if _sc is not None:
        try:
            _cp = [p if isinstance(p, dict) else {"policy_id": p} for p in (context.get("candidate_policies") or [])]
            _kw = {k: context[k] for k in ("components", "interaction_id", "observe_only") if context.get(k) and k in getattr(_sc.SiteDescriptor, "__dataclass_fields__", {})}
            _site = _sc.SiteDescriptor(site_id=context.get("site_id") or "", candidate_policies=_cp, fail_mode="BLOCK", source_type=source_type, destination_type=destination_type, **_kw)
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
# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
def _lineaje_load_gr_client():
    """Lineaje-added: load gr_stub_client.py without a pip dependency."""
    import sys as _s, importlib.util as _ilu
    from pathlib import Path as _P
    n = "_lineaje_gr_stub_client"
    if n in _s.modules: return _s.modules[n]
    h = _P(__file__).resolve().parent
    _cand = next((d / "gr_stub_client.py" for d in [h, *h.parents][:8] if (d / "gr_stub_client.py").is_file()), h / "gr_stub_client.py")
    _spec = _ilu.spec_from_file_location(n, _cand)
    _s.modules[n] = _m = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_m); return _m
def _lineaje_current_model():
    """Lineaje-added: reread the app's model setting for every request."""
    import os as _o
    from pathlib import Path as _P
    _keys = ("OPENROUTER_MODEL", "LLM_MODEL", "MODEL_NAME", "MODEL_ID", "OPENAI_MODEL", "ANTHROPIC_MODEL", "BEDROCK_MODEL_ID")
    _here = _P(__file__).resolve().parent
    for _path in (_here / ".env", *(_p / ".env" for _p in list(_here.parents)[:8])):
        if not _path.is_file(): continue
        try: _lines = _path.read_text(encoding="utf-8").splitlines()
        except OSError: continue
        _values = {}
        for _line in _lines:
            _line = _line.strip()
            if not _line or _line.startswith("#") or "=" not in _line: continue
            _key, _, _value = _line.partition("=")
            if _key.strip() in _keys: _values[_key.strip()] = _value.strip().strip(chr(34)).strip(chr(39))
        for _key in _keys:
            if _values.get(_key): return _values[_key]
    return next((_o.environ[_key].strip() for _key in _keys if _o.environ.get(_key, "").strip()), "")


import asyncio
from typing import Any

from .framework import AcmeLoanAgentFramework
from .helpers import extract_reference_number
from .mcp_servers import call_mcp_server


class SchedulingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "scheduling_agent"
    AGENT_NAME = "Scheduling Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "amazon nova lite"
    BEDROCK_MODEL_ID = "amazon.nova-lite-v1:0"
    DESCRIPTION = "Schedules borrower, underwriting, and support meetings."
    MCP_SERVERS = ["Google Calendar", "Email", "Slack"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Coordinate calendar events and notify the relevant teams."

    async def call_agent_model(self, user_message: str, meeting_reference: str) -> str:
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Meeting reference: {meeting_reference}\n"
                        f"Scheduling request: {user_message or 'Loan coordination meeting requested.'}\n\n"
                        "Draft a scheduling confirmation."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=180,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        meeting_reference = extract_reference_number(user_message, prefix="MEET")
        # LINEAJE: enforce() `user_message` at agent->llm pre_model — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_070 (Detect and block all forms of prompt injection attacks in user inputs and file contents). Mask/block; do not remove without review. site_id='site:sha256:ffe1354837ce0346bb61aa5011bbf7b31273aaf3703463eb21d4ffebb0fb0958'
        _lineaje_user_message_evidence = {'user_message': user_message, 'model': _lineaje_current_model(), 'project': 'Acme-Loan-5'}
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ffe1354837ce0346bb61aa5011bbf7b31273aaf3703463eb21d4ffebb0fb0958', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'policy_name': "Use only LLMs from the organization's approved list.", 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'policy_name': "Do not use LLMs from the organization's disallowed list", 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'policy_name': 'Detect and block all forms of prompt injection attacks in user inputs and file contents', 'guardrail_id': 'Sanitize Prompt Injection', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'policy_name': 'Do not send PII and/or secrets to AI Models', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_029', 'policy_name': 'Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='llm', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/scheduling_agent.py', 'line': 23, 'name': 'amazon.nova-lite-v1:0'}, 'destination': {'entity_type': 'llm', 'name': 'amazon nova lite', 'version': '', 'provider': ''}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'amazon.nova-lite-v1:0', 'version': '1.0.0', 'purl': 'pkg:aiagent/amazon.nova-lite-v1%3A0@1.0.0'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}, 'destination': {'entity_type': 'aimodel', 'name': 'Amazon Nova Lite', 'version': 'v1:0', 'purl': 'pkg:aimodel/Amazon%20Nova%20Lite@v1:0'}}, 'invocation': {'file': 'backend/agents/scheduling_agent.py', 'line': 47, 'function': 'SchedulingAgent.handle'}})
        try:
            _lineaje_user_message_evidence = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_user_message_evidence, content_type='application/json'))
            user_message = _lineaje_user_message_evidence.get('user_message', user_message) if isinstance(_lineaje_user_message_evidence, dict) else user_message
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        model_output = await self.call_agent_model(user_message, meeting_reference)
        try:
            import asyncio as _gr_asyncio
            await _gr_asyncio.to_thread(gr_check, {"activity": "llm_to_agent"}, "llm", "agent", observe_only=True, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:165cad3bbda2446662b23a3a4a8a202a2f5cf71b81cabc47881363c825993090', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_6dXylGIYVjVO6Lkf', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/scheduling_agent.py', 'line': 56, 'name': 'amazon.nova-lite-v1:0'}, 'destination': {'entity_type': 'llm', 'name': 'amazon nova lite', 'version': '', 'provider': ''}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'amazon.nova-lite-v1:0', 'version': '1.0.0', 'purl': 'pkg:aiagent/amazon.nova-lite-v1%3A0@1.0.0'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main?commit-id=1cc7c9eb98097f87153afd25cbc5a3d9e0e09f57&commit-time=2026-09-11%2021%3A14%3A53%20%2B0000&build_file=frontend/package.json&repo_strategy=single-repo'}, 'destination': {'entity_type': 'aimodel', 'name': 'Amazon Nova Lite', 'version': 'v1:0', 'purl': 'pkg:aimodel/Amazon%20Nova%20Lite@v1:0'}}, 'invocation': {'file': 'backend/agents/scheduling_agent.py', 'line': 91, 'function': 'SchedulingAgent.handle'}, 'file': 'backend/agents/scheduling_agent.py', 'line': 91, 'function': 'handle', 'agent_name': 'SchedulingAgent', 'agent_name_source': 'inferred_from_class', 'call_target': 'self.call_agent_model'}, interaction_id=locals().get('_lineaje_interaction_id'))
        except Exception:
            pass

        mcp_activity = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {meeting_reference}",
                    "description": user_message or "Loan coordination meeting requested.",
                    "start": "2026-04-01T10:00:00-07:00",
                    "end": "2026-04-01T10:30:00-07:00",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example", "underwriting@acme.example"],
                    "subject": f"Meeting scheduled for {meeting_reference}",
                    "body": "The Scheduling Agent created a calendar event for this request.",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Slack",
                "post_message",
                {
                    "channel": "#loan-ops",
                    "text": f"Scheduling Agent created meeting {meeting_reference}.",
                },
            ),
        )

        response = (
            f"Meeting reference: {meeting_reference}\n"
            f"Scheduling request: {user_message or 'No scheduling request provided.'}\n\n"
            f"Scheduling summary:\n{model_output}"
        )
        # LINEAJE: enforce() `response` at agent->user_interface data_egress — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.). Mask/block; do not remove without review. site_id='site:sha256:799f1e6c644f97fc7a63dfa19b8f460ffdb0632df2378315dd528f60d81cc64a'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:799f1e6c644f97fc7a63dfa19b8f460ffdb0632df2378315dd528f60d81cc64a', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/scheduling_agent.py', 'line': 23, 'name': 'amazon.nova-lite-v1:0'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'amazon.nova-lite-v1:0', 'version': '1.0.0', 'purl': 'pkg:aiagent/amazon.nova-lite-v1%3A0@1.0.0'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/scheduling_agent.py', 'line': 82, 'function': 'SchedulingAgent.handle'}})
        try:
            response = _gr_client.enforce(_gr_site, response, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }


scheduling_agent = SchedulingAgent()
