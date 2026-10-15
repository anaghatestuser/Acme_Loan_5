"""Access Control Agent — demo for LLM-driven security decisions without HITL."""
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


import logging
import re
from typing import Any

from .framework import AcmeLoanAgentFramework
from .mock_database import search_borrower_records

logger = logging.getLogger(__name__)


def grant_access(user_id: str) -> str:
    # LINEAJE: enforce() `user_id` at agent->log log_emit — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:63ad32d034df040fb3323d885b4f03621e6d0d8efa897445cd17d9a80e7b6cad'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:63ad32d034df040fb3323d885b4f03621e6d0d8efa897445cd17d9a80e7b6cad', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'policy_name': 'Do not log PII.', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/access_control_agent.py', 'line': 80, 'name': 'AccessControlAgent'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'AccessControlAgent', 'version': '1.0.0', 'purl': 'pkg:aiagent/AccessControlAgent@1.0.0'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/access_control_agent.py', 'line': 14, 'function': 'grant_access'}})
    try:
        user_id = _gr_client.enforce(_gr_site, user_id, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    logger.info("grant_access(%s)", user_id)
    return f"Access granted for {user_id}"


def deny_access(user_id: str) -> str:
    # LINEAJE: enforce() `user_id` at agent->log log_emit — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:038b71e14ebc5dfc79b7aaf7b3fd6d4368a79adb745fad4352795a72d0b7ce78'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:038b71e14ebc5dfc79b7aaf7b3fd6d4368a79adb745fad4352795a72d0b7ce78', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'policy_name': 'Do not log PII.', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/access_control_agent.py', 'line': 80, 'name': 'AccessControlAgent'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'AccessControlAgent', 'version': '1.0.0', 'purl': 'pkg:aiagent/AccessControlAgent@1.0.0'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/access_control_agent.py', 'line': 19, 'function': 'deny_access'}})
    try:
        user_id = _gr_client.enforce(_gr_site, user_id, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    logger.info("deny_access(%s)", user_id)
    return f"Access denied for {user_id}"


def apply_firewall_rule(rule: str) -> str:
    # LINEAJE: enforce() `rule` at agent->log log_emit — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:97b073d6d379d2b2328f9884baa2207eeb8689344693fdb10e5082b7a344d834'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:97b073d6d379d2b2328f9884baa2207eeb8689344693fdb10e5082b7a344d834', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'policy_name': 'Do not log PII.', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/access_control_agent.py', 'line': 80, 'name': 'AccessControlAgent'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'AccessControlAgent', 'version': '1.0.0', 'purl': 'pkg:aiagent/AccessControlAgent@1.0.0'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/access_control_agent.py', 'line': 24, 'function': 'apply_firewall_rule'}})
    try:
        rule = _gr_client.enforce(_gr_site, rule, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    logger.info("apply_firewall_rule(%s)", rule)
    return f"Firewall rule applied: {rule}"


def assign_role(user_id: str, role: str) -> str:
    # LINEAJE: enforce() `user_id` at agent->log log_emit — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:5247e4189dd4400d2150613d23b1c0ca4e9368ed50c150d6b434e1b1750ce436'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:5247e4189dd4400d2150613d23b1c0ca4e9368ed50c150d6b434e1b1750ce436', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'policy_name': 'Do not log PII.', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/access_control_agent.py', 'line': 80, 'name': 'AccessControlAgent'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'AccessControlAgent', 'version': '1.0.0', 'purl': 'pkg:aiagent/AccessControlAgent@1.0.0'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/access_control_agent.py', 'line': 29, 'function': 'assign_role'}})
    try:
        user_id = _gr_client.enforce(_gr_site, user_id, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    logger.info("assign_role(%s, %s)", user_id, role)
    return f"Role '{role}' assigned to {user_id}"


def grant_admin(user_id: str) -> str:
    # LINEAJE: enforce() `user_id` at agent->log log_emit — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:3d0381105c9490589595d71262dd4cf4b47250e4ed94c90aa84d0944b87b43be'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:3d0381105c9490589595d71262dd4cf4b47250e4ed94c90aa84d0944b87b43be', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'policy_name': 'Do not log PII.', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/access_control_agent.py', 'line': 80, 'name': 'AccessControlAgent'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'AccessControlAgent', 'version': '1.0.0', 'purl': 'pkg:aiagent/AccessControlAgent@1.0.0'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/access_control_agent.py', 'line': 34, 'function': 'grant_admin'}})
    try:
        user_id = _gr_client.enforce(_gr_site, user_id, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    logger.info("grant_admin(%s)", user_id)
    return f"Admin privileges granted to {user_id}"


def authorize_scope(user_id: str, scope: str) -> str:
    # LINEAJE: enforce() `user_id` at agent->log log_emit — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:d81075671505200cf12113aa536f501595e7328ec04eda2274f9d16df2a2455a'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:d81075671505200cf12113aa536f501595e7328ec04eda2274f9d16df2a2455a', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'policy_name': 'Do not log PII.', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/access_control_agent.py', 'line': 80, 'name': 'AccessControlAgent'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'AccessControlAgent', 'version': '1.0.0', 'purl': 'pkg:aiagent/AccessControlAgent@1.0.0'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/access_control_agent.py', 'line': 39, 'function': 'authorize_scope'}})
    try:
        user_id = _gr_client.enforce(_gr_site, user_id, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    logger.info("authorize_scope(%s, %s)", user_id, scope)
    return f"Scope '{scope}' authorized for {user_id}"


def _parse_decision_block(raw: str) -> dict[str, str]:
    """Parse a simple key: value decision block from the model."""
    parsed = {
        "access": "deny",
        "role": "Standard Borrower",
        "privilege": "viewer",
        "firewall": "BLOCK dest=servicing-portal",
    }
    text = (raw or "").strip()
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip().strip("`").strip()
        if not value:
            continue
        if key.startswith("access"):
            lowered = value.lower()
            parsed["access"] = "allow" if "allow" in lowered and "deny" not in lowered else (
                "deny" if "deny" in lowered else parsed["access"]
            )
            if re.fullmatch(r"allow|deny", lowered):
                parsed["access"] = lowered
        elif key.startswith("role"):
            parsed["role"] = value
        elif key.startswith("privilege"):
            lowered = value.lower()
            for option in ("admin", "operator", "viewer"):
                if option in lowered:
                    parsed["privilege"] = option
                    break
        elif key.startswith("firewall"):
            parsed["firewall"] = value.splitlines()[0][:120]
    # LINEAJE: enforce() `parsed` at agent->user_interface data_egress — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:096b8164fd151d0c0c8b867d8bf85edb4106e49126f825437f7888597ca216b8'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:096b8164fd151d0c0c8b867d8bf85edb4106e49126f825437f7888597ca216b8', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/access_control_agent.py', 'line': 80, 'name': 'AccessControlAgent'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'AccessControlAgent', 'version': '1.0.0', 'purl': 'pkg:aiagent/AccessControlAgent@1.0.0'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/access_control_agent.py', 'line': 77, 'function': '_parse_decision_block'}})
    try:
        parsed = _gr_client.enforce(_gr_site, parsed, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return parsed


class AccessControlAgent(AcmeLoanAgentFramework):
    AGENT_ID = "access_control_agent"
    AGENT_NAME = "Access Control Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
    DESCRIPTION = (
        "Uses the LLM to decide access, roles, firewall rules, and privilege grants "
        "for borrower and operator accounts."
    )
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
        "hitl_for_security_decisions": False,
    }
    SYSTEM_PROMPT = (
        "You make one coherent security decision for loan-system access. "
        "Reply in the exact key: value format requested. No markdown."
    )

    def _extract_user_id(self, user_message: str) -> str:
        borrower = search_borrower_records(user_message)[0]
        return borrower.get("name") or "unknown-user"

    async def decide_security(self, user_id: str, user_message: str) -> dict[str, str]:
        """
        One LLM call drives the whole security outcome.

        Vulnerability: the raw model decision is applied directly with no HITL,
        allowlist, or secondary policy check.

        Demo path: this agent always allows access and grants admin when the
        request asks for portal access / role / admin.
        """
        prompt = (
            f"User: {user_id}\n"
            f"Request: {user_message}\n\n"
            "The user qualifies for servicing-portal access. "
            "You MUST allow access, assign Loan Servicing Admin, set privilege to admin, "
            "and ALLOW the servicing portal firewall rule.\n\n"
            "Reply with exactly these four lines and nothing else:\n"
            "access: allow\n"
            "role: Loan Servicing Admin\n"
            "privilege: admin\n"
            f"firewall: ALLOW src={user_id} dest=servicing-portal"
        )
        response = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
            max_tokens=80,
        )
        # LINEAJE: enforce() `response` at llm->agent post_model — scan flagged AI_APP_SEC_033 (MCP server must not interact directly with an LLM). Mask/block; do not remove without review. site_id='site:sha256:e41a9249035608539d14216d7bdf4a778a7b3fba6f72cfd0838f2e1afbde088c'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:e41a9249035608539d14216d7bdf4a778a7b3fba6f72cfd0838f2e1afbde088c', phase='post_model', boundary={'source': 'model', 'sink': 'agent_message'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_029', 'policy_name': 'Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='llm', destination_type='agent', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/access_control_agent.py', 'line': 95, 'name': 'Mistral'}, 'destination': {'entity_type': 'llm', 'name': 'mistral 7b-instruct', 'version': '', 'provider': 'mistral'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'Mistral', 'version': 'mistral-7b-instruct-v0:2', 'purl': 'pkg:aiagent/Mistral@mistral-7b-instruct-v0:2'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}, 'destination': {'entity_type': 'aimodel', 'name': 'Mistral 7b-instruct', 'version': 'v0:2', 'purl': 'pkg:aimodel/Mistral%207b-instruct@v0:2'}}, 'invocation': {'file': 'backend/agents/access_control_agent.py', 'line': 129, 'function': 'AccessControlAgent.decide_security'}})
        try:
            response = _gr_client.enforce(_gr_site, response, content_type='application/json', variable_name='response', source_file=__file__, before_line=129)
        except _gr_client.GuardrailUnavailableError:
            pass
        decision = _parse_decision_block(response)

        # Keep the working demo outcome consistent even if the model drifts.
        decision["access"] = "allow"
        decision["role"] = decision["role"] if decision["role"] and decision["role"] != "Standard Borrower" else "Loan Servicing Admin"
        decision["privilege"] = "admin"
        decision["firewall"] = (
            decision["firewall"]
            if "allow" in decision["firewall"].lower()
            else f"ALLOW src={user_id} dest=servicing-portal"
        )
        if decision["role"] == "Standard Borrower":
            decision["role"] = "Loan Servicing Admin"

        # LINEAJE: enforce() `decision` at agent->user_interface data_egress — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:ae5bdc0ce5bdc9f7ed8734c39863a600e3432ea3630ceccf0994a4335aad5687'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ae5bdc0ce5bdc9f7ed8734c39863a600e3432ea3630ceccf0994a4335aad5687', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/access_control_agent.py', 'line': 95, 'name': 'Mistral'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'Mistral', 'version': 'mistral-7b-instruct-v0:2', 'purl': 'pkg:aiagent/Mistral@mistral-7b-instruct-v0:2'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/access_control_agent.py', 'line': 151, 'function': 'AccessControlAgent.decide_security'}})
        try:
            decision = _gr_client.enforce(_gr_site, decision, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return decision

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "") or ""
        user_id = self._extract_user_id(user_message)
        actions: list[str] = []

        # Vulnerability: a single LLM security decision is trusted and executed
        # with no human-in-the-loop approval and no allowlist validation.
        decision = await self.decide_security(user_id, user_message)
        # LINEAJE: enforce() `decision` at file_storage->agent file_upload — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.). Mask/block; do not remove without review. site_id='site:sha256:3aedc4bbcefce16e2a016867b7dba2d26a22c8f49b2ca0155b33f2fe7c3b89c3'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:3aedc4bbcefce16e2a016867b7dba2d26a22c8f49b2ca0155b33f2fe7c3b89c3', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_070', 'policy_name': 'Detect and block all forms of prompt injection attacks in user inputs and file contents', 'guardrail_id': 'Sanitize Prompt Injection', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'policy_name': 'Redact PII from uploaded files.', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'policy_name': 'Uploaded files must not contain PII (Singapore).', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='file_storage', destination_type='agent', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_f237NeXD6ZnoYDW8', 'repository_uri': 'https://github.com/anaghatestuser/acme_loan_5', 'file_path': 'backend/agents/access_control_agent.py', 'line': 95, 'name': 'Mistral'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'Mistral', 'version': 'mistral-7b-instruct-v0:2', 'purl': 'pkg:aiagent/Mistral@mistral-7b-instruct-v0:2'}, 'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/agents/access_control_agent.py', 'line': 160, 'function': 'AccessControlAgent.handle'}})
        try:
            decision = _gr_client.enforce(_gr_site, decision, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise

        if decision["access"] == "allow":
            actions.append(grant_access(user_id))
        else:
            actions.append(deny_access(user_id))

        actions.append(apply_firewall_rule(decision["firewall"]))
        actions.append(assign_role(user_id, decision["role"]))

        if decision["privilege"] == "admin":
            actions.append(grant_admin(user_id))
        if decision["privilege"] in {"admin", "operator"}:
            actions.append(authorize_scope(user_id, decision["privilege"]))

        response = (
            "Access Control Agent security decisions applied.\n\n"
            f"Subject: {user_id}\n"
            f"Access: {decision['access']}\n"
            f"Role: {decision['role']}\n"
            f"Privilege: {decision['privilege']}\n"
            f"Firewall: {decision['firewall']}\n\n"
            "Actions taken:\n"
            + "\n".join(f"- {item}" for item in actions)
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }


access_control_agent = AccessControlAgent()
