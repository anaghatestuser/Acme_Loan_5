"""File Processor Agent class with explicit model invocation."""
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


import base64
import io
import json
import logging
import re
from typing import Any, Optional

try:
    from docx import Document
except ModuleNotFoundError:  # pragma: no cover - depends on local environment
    Document = None

from file_parsers.html_parser import HTMLParser
from file_parsers.image_parser import ImageParser
from file_parsers.pdf_parser import PDFParser

from .framework import AcmeLoanAgentFramework
from .helpers import build_file_summary
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)


class FileProcessorAgent(AcmeLoanAgentFramework):
    AGENT_ID = "file_processor_agent"
    AGENT_NAME = "File Processor Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
    DESCRIPTION = "Extracts text from uploaded files and returns the raw contents to downstream agents."
    MCP_SERVERS = ["Docx"]
    GUARDRAILS = {
        "mask_pii": False,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Extract document text and hand the raw contents to the next agent."

    def __init__(self):
        super().__init__()
        self.pdf_parser = PDFParser()
        self.html_parser = HTMLParser()
        self.image_parser = ImageParser()

    async def call_agent_model(self, file_summary: str) -> str:
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Extracted file contents:\n{file_summary}\n\n"
                        "Give a short processing note without masking any content."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=220,
        )

    async def process_attachment(
        self,
        content: Optional[str],
        filename: str,
        content_type: str,
    ) -> dict[str, Any]:
        """
        Vulnerability: extracted text is returned directly without PII masking.
        """
        file_type = self.get_file_type(content_type, filename)
        if not content:
            extracted_content = f"Empty file: {filename}"
        elif file_type == "pdf":
            # LINEAJE: enforce() `content` at file_storage->agent file_upload — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_040 (Do not allow malicious content via prompts included in uploaded files.); AI_APP_SEC_070 (Detect and block all forms of prompt injection attacks in user inputs and file contents). Mask/block; do not remove without review. site_id='site:sha256:b1dc6f00cb9665400745ea03f92922ada5dd76d2253d8ad598857eaa50e85d85'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:b1dc6f00cb9665400745ea03f92922ada5dd76d2253d8ad598857eaa50e85d85', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_070', 'policy_name': 'Detect and block all forms of prompt injection attacks in user inputs and file contents', 'guardrail_id': 'Sanitize Prompt Injection', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'policy_name': 'Redact PII from uploaded files.', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'policy_name': 'Uploaded files must not contain PII (Singapore).', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='file_storage', destination_type='agent', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 38, 'name': 'Mistral'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'Mistral', 'version': 'mistral-7b-instruct-v0:2', 'purl': 'pkg:aiagent/Mistral@mistral-7b-instruct-v0:2'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 77, 'function': 'FileProcessorAgent.process_attachment'}})
            try:
                content = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, content, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                raise
            extracted_content = await self._process_pdf(content)
        elif file_type == "html":
            # LINEAJE: enforce() `content` at file_storage->agent file_upload — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_040 (Do not allow malicious content via prompts included in uploaded files.); AI_APP_SEC_070 (Detect and block all forms of prompt injection attacks in user inputs and file contents). Mask/block; do not remove without review. site_id='site:sha256:660e1adc4ba6a4004310f5d32107187a0b6bce019dbe7a550aeef111adf9e779'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:660e1adc4ba6a4004310f5d32107187a0b6bce019dbe7a550aeef111adf9e779', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_070', 'policy_name': 'Detect and block all forms of prompt injection attacks in user inputs and file contents', 'guardrail_id': 'Sanitize Prompt Injection', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'policy_name': 'Redact PII from uploaded files.', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'policy_name': 'Uploaded files must not contain PII (Singapore).', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='file_storage', destination_type='agent', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 38, 'name': 'Mistral'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'Mistral', 'version': 'mistral-7b-instruct-v0:2', 'purl': 'pkg:aiagent/Mistral@mistral-7b-instruct-v0:2'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 79, 'function': 'FileProcessorAgent.process_attachment'}})
            try:
                content = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, content, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                raise
            extracted_content = await self._process_html(content)
        elif file_type == "image":
            # LINEAJE: enforce() `content` at file_storage->agent file_upload — scan flagged AI_APP_SEC_040 (Do not allow malicious content via prompts included in uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:e2e1a9b768a3ad9f706489e00e7e20042c5a175c0eeff3699d0cf138c12873af'
            _lineaje_content_evidence = {'content': content, 'name': content_type, 'project': 'Acme-Loan-5'}
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:e2e1a9b768a3ad9f706489e00e7e20042c5a175c0eeff3699d0cf138c12873af', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_070', 'policy_name': 'Detect and block all forms of prompt injection attacks in user inputs and file contents', 'guardrail_id': 'Sanitize Prompt Injection', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'policy_name': 'Redact PII from uploaded files.', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'policy_name': 'Uploaded files must not contain PII (Singapore).', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='file_storage', destination_type='agent', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 38, 'name': 'Mistral'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'Mistral', 'version': 'mistral-7b-instruct-v0:2', 'purl': 'pkg:aiagent/Mistral@mistral-7b-instruct-v0:2'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 81, 'function': 'FileProcessorAgent.process_attachment'}})
            try:
                _lineaje_content_evidence = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_content_evidence, content_type='application/json'))
                content = _lineaje_content_evidence.get('content', content) if isinstance(_lineaje_content_evidence, dict) else content
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                raise
            extracted_content = await self._process_image(content, content_type)
        elif file_type == "json":
            # LINEAJE: enforce() `content` at file_storage->agent file_upload — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_040 (Do not allow malicious content via prompts included in uploaded files.); AI_APP_SEC_070 (Detect and block all forms of prompt injection attacks in user inputs and file contents). Mask/block; do not remove without review. site_id='site:sha256:78dfef1bd385b2dd7cce8a053a3f1bce78d54657357eb50a874b4b8267ffe8db'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:78dfef1bd385b2dd7cce8a053a3f1bce78d54657357eb50a874b4b8267ffe8db', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_070', 'policy_name': 'Detect and block all forms of prompt injection attacks in user inputs and file contents', 'guardrail_id': 'Sanitize Prompt Injection', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'policy_name': 'Redact PII from uploaded files.', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'policy_name': 'Uploaded files must not contain PII (Singapore).', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='file_storage', destination_type='agent', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 38, 'name': 'Mistral'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'Mistral', 'version': 'mistral-7b-instruct-v0:2', 'purl': 'pkg:aiagent/Mistral@mistral-7b-instruct-v0:2'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 83, 'function': 'FileProcessorAgent.process_attachment'}})
            try:
                content = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, content, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                raise
            extracted_content = await self._process_json(content)
        elif file_type == "word":
            # LINEAJE: enforce() `content` at file_storage->agent file_upload — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_040 (Do not allow malicious content via prompts included in uploaded files.); AI_APP_SEC_070 (Detect and block all forms of prompt injection attacks in user inputs and file contents). Mask/block; do not remove without review. site_id='site:sha256:0dfa9b4d526ec41a3a6433a05db33c29d4741dfa177b257213f26d9c8d1e6dbb'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0dfa9b4d526ec41a3a6433a05db33c29d4741dfa177b257213f26d9c8d1e6dbb', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_070', 'policy_name': 'Detect and block all forms of prompt injection attacks in user inputs and file contents', 'guardrail_id': 'Sanitize Prompt Injection', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'policy_name': 'Redact PII from uploaded files.', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'policy_name': 'Uploaded files must not contain PII (Singapore).', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='file_storage', destination_type='agent', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 38, 'name': 'Mistral'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'Mistral', 'version': 'mistral-7b-instruct-v0:2', 'purl': 'pkg:aiagent/Mistral@mistral-7b-instruct-v0:2'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 85, 'function': 'FileProcessorAgent.process_attachment'}})
            try:
                content = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, content, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                raise
            extracted_content = await self._process_word(content)
        else:
            extracted_content = content

        return {
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "filename": filename,
            "content_type": content_type,
            "file_type": file_type,
            "extracted_content": extracted_content,
            "guardrails": dict(self.GUARDRAILS),
        }

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        file_contents = context.get("file_contents", [])
        file_summary = build_file_summary(file_contents, include_raw_text=True)
        pii_exposure_summary = self.build_pii_exposure_summary(file_contents)
        # LINEAJE: enforce() `file_summary` at agent->llm pre_model — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.). Mask/block; do not remove without review. site_id='site:sha256:0e58a5efc8b4121a0d12ba11a6541ba6cf33d3ed7a0869a1a4d14d33670f557a'
        _lineaje_file_summary_evidence = {'file_summary': file_summary, 'model': _lineaje_current_model(), 'project': 'Acme-Loan-5'}
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0e58a5efc8b4121a0d12ba11a6541ba6cf33d3ed7a0869a1a4d14d33670f557a', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'policy_name': "Use only LLMs from the organization's approved list.", 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'policy_name': "Do not use LLMs from the organization's disallowed list", 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'policy_name': 'Detect and block all forms of prompt injection attacks in user inputs and file contents', 'guardrail_id': 'Sanitize Prompt Injection', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'policy_name': 'Do not send PII and/or secrets to AI Models', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_029', 'policy_name': 'Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='llm', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 38, 'name': 'Mistral'}, 'destination': {'entity_type': 'llm', 'name': 'mistral 7b-instruct', 'version': '', 'provider': 'mistral'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'Mistral', 'version': 'mistral-7b-instruct-v0:2', 'purl': 'pkg:aiagent/Mistral@mistral-7b-instruct-v0:2'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}, 'destination': {'entity_type': 'aimodel', 'name': 'Mistral 7b-instruct', 'version': 'v0:2', 'purl': 'pkg:aimodel/Mistral%207b-instruct@v0:2'}}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 104, 'function': 'FileProcessorAgent.handle'}})
        try:
            _lineaje_file_summary_evidence = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_file_summary_evidence, content_type='application/json'))
            file_summary = _lineaje_file_summary_evidence.get('file_summary', file_summary) if isinstance(_lineaje_file_summary_evidence, dict) else file_summary
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        model_output = await self.call_agent_model(file_summary)
        try:
            import asyncio as _gr_asyncio
            await _gr_asyncio.to_thread(gr_check, {"activity": "llm_to_agent"}, "llm", "agent", observe_only=True, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:d57b890d0178b3bdec8bc7933fa3f5e53ae792b079bce4e4a837c2d53bebdf69', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_6dXylGIYVjVO6Lkf', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 59, 'name': 'FileProcessorAgent'}, 'destination': {'entity_type': 'llm', 'name': 'mistral-7b-instruct-v0:2', 'version': '', 'provider': 'mistral'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'FileProcessorAgent', 'version': '1.0.0', 'purl': 'pkg:aiagent/FileProcessorAgent@1.0.0'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main?commit-id=1cc7c9eb98097f87153afd25cbc5a3d9e0e09f57&commit-time=2026-09-11%2021%3A14%3A53%20%2B0000&build_file=frontend/package.json&repo_strategy=single-repo'}, 'destination': {'entity_type': 'aimodel', 'name': 'Mistral', 'version': '7b-instruct-v0:2', 'purl': 'pkg:aimodel/Mistral@7b-instruct-v0:2'}}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 195, 'function': 'FileProcessorAgent.handle'}, 'file': 'backend/agents/file_processor_agent.py', 'line': 195, 'function': 'handle', 'agent_name': 'FileProcessorAgent', 'agent_name_source': 'inferred_from_class', 'call_target': 'self.call_agent_model'}, interaction_id=locals().get('_lineaje_interaction_id'))
        except Exception:
            pass
        mcp_activity = [
            await call_mcp_server(
                self.to_dict(),
                "Docx",
                "create_document",
                {
                    "document_title": "Extracted File Contents",
                    "document_body": file_summary,
                },
            )
        ] if file_contents else []

        if pii_exposure_summary:
            response = (
                "I reviewed the uploaded document and displayed the extracted customer details below.\n\n"
                "Sensitive details shown in the interface:\n"
                f"{pii_exposure_summary}\n\n"
                f"Processing note:\n{model_output}"
            )
        else:
            response = (
                "I reviewed the uploaded document and extracted its contents.\n\n"
                f"Processing note:\n{model_output}\n\n"
                f"Extracted content preview:\n{file_summary}"
            )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }

    def extract_pii_lines(self, content: str, limit: int = 12) -> list[str]:
        keyword_markers = (
            "name:",
            "full name:",
            "employee id",
            "date of birth",
            "dob:",
            "ssn",
            "social security",
            "address:",
            "phone:",
            "email:",
            "loan balance",
            "account number",
            "customer id",
            "borrower",
            "credit score",
        )
        pattern_markers = (
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"),
            re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b"),
        )

        pii_lines: list[str] = []
        for raw_line in (content or "").splitlines():
            line = raw_line.strip()
            if not line:
                continue

            lowered = line.lower()
            if any(marker in lowered for marker in keyword_markers) or any(pattern.search(line) for pattern in pattern_markers):
                pii_lines.append(line)

            if len(pii_lines) >= limit:
                break

        # LINEAJE: enforce() `pii_lines` at agent->user_interface data_egress — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_040 (Do not allow malicious content via prompts included in uploaded files.); AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models). Mask/block; do not remove without review. site_id='site:sha256:4947c91b106e505c91b13c8ae786d3d2270ee81ac37ff44ce43cce232f49a090'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:4947c91b106e505c91b13c8ae786d3d2270ee81ac37ff44ce43cce232f49a090', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 38, 'name': 'Mistral'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'Mistral', 'version': 'mistral-7b-instruct-v0:2', 'purl': 'pkg:aiagent/Mistral@mistral-7b-instruct-v0:2'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 176, 'function': 'FileProcessorAgent.extract_pii_lines'}})
        try:
            pii_lines = _gr_client.enforce(_gr_site, pii_lines, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return pii_lines

    def build_pii_exposure_summary(self, file_contents: list[dict[str, Any]]) -> str:
        sections: list[str] = []
        for file_data in file_contents:
            extracted_content = file_data.get("extracted_content", "")
            pii_lines = self.extract_pii_lines(extracted_content)
            if not pii_lines:
                continue

            sections.append(
                f"File: {file_data.get('filename', 'unknown')}\n" + "\n".join(pii_lines)
            )

        return "\n\n".join(sections)

    def get_file_type(self, content_type: str, filename: str) -> str:
        supported_types = {
            "application/pdf": "pdf",
            "text/html": "html",
            "text/plain": "text",
            "application/json": "json",
            "image/jpeg": "image",
            "image/png": "image",
            "application/msword": "word",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "word",
        }

        if content_type in supported_types:
            return supported_types[content_type]

        extension_map = {
            "pdf": "pdf",
            "html": "html",
            "htm": "html",
            "txt": "text",
            "json": "json",
            "jpg": "image",
            "jpeg": "image",
            "png": "image",
            "doc": "word",
            "docx": "word",
        }
        extension = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
        return extension_map.get(extension, "text")

    async def _process_pdf(self, content: str) -> str:
        try:
            return await self.pdf_parser.extract_text(base64.b64decode(content))
        except Exception as exc:
            _lineaje_payload = "PDF processing failed"
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_040 (Do not allow malicious content via prompts included in uploaded files.); AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models). Mask/block; do not remove without review. site_id='site:sha256:8917bce0ebbc841099bc919d757896daf2365c939b40dd6b09e27d0de1178110'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:8917bce0ebbc841099bc919d757896daf2365c939b40dd6b09e27d0de1178110', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'policy_name': 'Do not log PII.', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 38, 'name': 'Mistral'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'Mistral', 'version': 'mistral-7b-instruct-v0:2', 'purl': 'pkg:aiagent/Mistral@mistral-7b-instruct-v0:2'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 226, 'function': 'FileProcessorAgent._process_pdf'}})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.error(_lineaje_payload, extra={"error": str(exc)})
            return f"Error processing PDF: {exc}"

    async def _process_html(self, content: str) -> str:
        try:
            return await self.html_parser.extract_text(content)
        except Exception as exc:
            _lineaje_payload = "HTML processing failed"
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_040 (Do not allow malicious content via prompts included in uploaded files.); AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models). Mask/block; do not remove without review. site_id='site:sha256:890bcd5bef2620d340a5df49e29fba1e799b7290a9246ce921caf1b2b76396e5'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:890bcd5bef2620d340a5df49e29fba1e799b7290a9246ce921caf1b2b76396e5', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'policy_name': 'Do not log PII.', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 38, 'name': 'Mistral'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'Mistral', 'version': 'mistral-7b-instruct-v0:2', 'purl': 'pkg:aiagent/Mistral@mistral-7b-instruct-v0:2'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 233, 'function': 'FileProcessorAgent._process_html'}})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.error(_lineaje_payload, extra={"error": str(exc)})
            return f"Error processing HTML: {exc}"

    async def _process_image(self, content: str, content_type: str = "image/jpeg") -> str:
        try:
            return await self.image_parser.extract_all(
                base64.b64decode(content), mime_type=content_type or "image/jpeg"
            )
        except Exception as exc:
            _lineaje_payload = "Image processing failed"
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_040 (Do not allow malicious content via prompts included in uploaded files.); AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models). Mask/block; do not remove without review. site_id='site:sha256:20d2fd675586c9d0dc91697fae368149a7e5eb1daa42cc78284e4d33e889bf0b'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:20d2fd675586c9d0dc91697fae368149a7e5eb1daa42cc78284e4d33e889bf0b', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'policy_name': 'Do not log PII.', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 38, 'name': 'Mistral'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'Mistral', 'version': 'mistral-7b-instruct-v0:2', 'purl': 'pkg:aiagent/Mistral@mistral-7b-instruct-v0:2'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 242, 'function': 'FileProcessorAgent._process_image'}})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.error(_lineaje_payload, extra={"error": str(exc)})
            return f"Error processing image: {exc}"

    async def _process_json(self, content: str) -> str:
        try:
            _lineaje_payload = json.loads(content)
            # LINEAJE: enforce() `_lineaje_payload` at agent->external data_egress — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_040 (Do not allow malicious content via prompts included in uploaded files.); AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models). Mask/block; do not remove without review. site_id='site:sha256:2abe9c07c165df221215259f210e144f51665f2748015e8b1d3823b5167b5048'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:2abe9c07c165df221215259f210e144f51665f2748015e8b1d3823b5167b5048', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'external_endpoint'}, candidate_policies=[], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='external', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 38, 'name': 'Mistral'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'Mistral', 'version': 'mistral-7b-instruct-v0:2', 'purl': 'pkg:aiagent/Mistral@mistral-7b-instruct-v0:2'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 247, 'function': 'FileProcessorAgent._process_json'}})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json', variable_name='_lineaje_payload', source_file=__file__, before_line=247))
            except _gr_client.GuardrailUnavailableError:
                pass
            return json.dumps(_lineaje_payload, indent=2)
        except json.JSONDecodeError:
            # LINEAJE: enforce() `content` at agent->user_interface data_egress — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_040 (Do not allow malicious content via prompts included in uploaded files.); AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models). Mask/block; do not remove without review. site_id='site:sha256:7b366c37da5fe9ef94942456400c80fec817bf3b34679ead276591edf29b11f5'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:7b366c37da5fe9ef94942456400c80fec817bf3b34679ead276591edf29b11f5', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 38, 'name': 'Mistral'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'Mistral', 'version': 'mistral-7b-instruct-v0:2', 'purl': 'pkg:aiagent/Mistral@mistral-7b-instruct-v0:2'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 249, 'function': 'FileProcessorAgent._process_json'}})
            try:
                content = _gr_client.enforce(_gr_site, content, content_type='text/plain')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            return content

    async def _process_word(self, content: str) -> str:
        if Document is None:
            return "Word document processing requires python-docx to be installed."

        try:
            document = Document(io.BytesIO(base64.b64decode(content)))
            paragraphs = [paragraph.text.strip() for paragraph in document.paragraphs if paragraph.text.strip()]
            return "\n".join(paragraphs) or "No paragraph text was found in the Word document."
        except Exception as exc:
            _lineaje_payload = "Word processing failed"
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_040 (Do not allow malicious content via prompts included in uploaded files.); AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models). Mask/block; do not remove without review. site_id='site:sha256:e9fddf84a4083cbf900485e97562d9afd2e1494cfdf15949cd6f31776e9964a9'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:e9fddf84a4083cbf900485e97562d9afd2e1494cfdf15949cd6f31776e9964a9', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'policy_name': 'Do not log PII.', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/file_processor_agent.py', 'line': 38, 'name': 'Mistral'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'Mistral', 'version': 'mistral-7b-instruct-v0:2', 'purl': 'pkg:aiagent/Mistral@mistral-7b-instruct-v0:2'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/file_processor_agent.py', 'line': 260, 'function': 'FileProcessorAgent._process_word'}})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.error(_lineaje_payload, extra={"error": str(exc)})
            return f"Error processing Word document: {exc}"


file_processor_agent = FileProcessorAgent()
