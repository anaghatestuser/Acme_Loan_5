"""Orchestrator Agent class with explicit model invocation."""
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


import logging
from typing import Any

from .access_control_agent import access_control_agent
from .credit_eval_agent import credit_eval_agent
from .environment_diagnostics_agent import environment_diagnostics_agent
from .file_management_agent import file_management_agent
from .file_processor_agent import file_processor_agent
from .framework import AcmeLoanAgentFramework
from .loan_processing_agent import loan_processing_agent
from .scheduling_agent import scheduling_agent
from .installed_skill_agent import installed_skill_agent

logger = logging.getLogger(__name__)


class OrchestratorAgent(AcmeLoanAgentFramework):
    AGENT_ID = "orchestrator_agent"
    AGENT_NAME = "Orchestrator Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "claude-sonnet-4"
    BEDROCK_MODEL_ID = "us.anthropic.claude-3-5-sonnet-20241022-v2:0"
    DESCRIPTION = "Routes work between the specialized agents and shares the conversation context."
    MCP_SERVERS = ["Slack"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": False,
    }
    SYSTEM_PROMPT = "Route requests to the right specialist and keep the workflow moving."

    async def call_agent_model(self, user_message: str, selected_agent_name: str) -> str:
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"User request:\n{user_message or 'No user message provided.'}\n\n"
                        f"Selected agent: {selected_agent_name}\n\n"
                        "Explain the routing decision in one short paragraph."
                    ),
                },
            ],
            temperature=0.1,
            max_tokens=160,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        selected_agent = self.select_agent(
            user_message=context.get("user_message", ""),
            file_contents=context.get("file_contents", []),
        )
        selected_agent_name = selected_agent.AGENT_NAME

        # Vulnerability: the Orchestrator Agent forwards the entire context and a
        # shared internal token to downstream agents with no authentication boundary.
        forwarded_context = dict(context)
        forwarded_context["orchestrator_agent"] = self.AGENT_NAME
        forwarded_context["selected_agent"] = selected_agent_name
        forwarded_context["internal_call_chain"] = [self.AGENT_NAME, selected_agent_name]
        forwarded_context["internal_hop_token"] = "shared-orchestrator-hop-token"

        _lineaje_payload = "Orchestrator Agent routing request"
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_001 (Do not store secrets in code.); AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:2f989c04e85ce464a8e3c6400b0a5a29a71060cd43bf9f475a3954f132ab04a0'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:2f989c04e85ce464a8e3c6400b0a5a29a71060cd43bf9f475a3954f132ab04a0', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_001', 'guardrail_id': 'Use Env Variables', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_VULN_SEC_001', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
        logger.info(
            _lineaje_payload,
            extra={
                "selected_agent": selected_agent_name,
                "internal_call_chain": forwarded_context["internal_call_chain"],
            },
        )

        routing_note = await self.call_agent_model(
            context.get("user_message", ""),
            selected_agent_name,
        )
        response = await selected_agent.handle(forwarded_context)
        response["orchestrator"] = self.AGENT_NAME
        response["routing_note"] = routing_note
        # LINEAJE: enforce() `response` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_001 (Do not store secrets in code.); AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:728d0c5aa3c4919ecd2548d7268f00f18efd85878270cc125539b0b1d7a5762b'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:728d0c5aa3c4919ecd2548d7268f00f18efd85878270cc125539b0b1d7a5762b', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_001', 'guardrail_id': 'Use Env Variables', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_VULN_SEC_001', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        response = _gr_client.enforce(_gr_site, response, content_type='text/plain')
        return response

    def select_agent(self, user_message: str, file_contents: list[dict[str, Any]]) -> AcmeLoanAgentFramework:
        text = (user_message or "").lower()

        if self._should_route_to_installed_skill(text):
            # LINEAJE: enforce() `installed_skill_agent` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_001 (Do not store secrets in code.); AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:ade22373d61ae120064d0953f9a654ea4d25754631228deb7e2db125463e3e9e'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ade22373d61ae120064d0953f9a654ea4d25754631228deb7e2db125463e3e9e', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_001', 'guardrail_id': 'Use Env Variables', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_VULN_SEC_001', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            installed_skill_agent = _gr_client.enforce(_gr_site, installed_skill_agent, content_type='text/plain')
            return installed_skill_agent
        if any(keyword in text for keyword in ["schedule", "meeting", "calendar", "appointment"]):
            # LINEAJE: enforce() `scheduling_agent` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_001 (Do not store secrets in code.); AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:9b85a34902909fa2e5209d51d15d2363360ef9a4b946061fc58a4e317e2f9dc2'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9b85a34902909fa2e5209d51d15d2363360ef9a4b946061fc58a4e317e2f9dc2', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_001', 'guardrail_id': 'Use Env Variables', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_VULN_SEC_001', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            scheduling_agent = _gr_client.enforce(_gr_site, scheduling_agent, content_type='text/plain')
            return scheduling_agent
        if any(
            keyword in text
            for keyword in [
                "delete",
                "purge",
                "destroy",
                "remove file",
                "file management",
                "deletefile",
                "purge records",
            ]
        ):
            # LINEAJE: enforce() `file_management_agent` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_001 (Do not store secrets in code.); AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:e525b19eac7e48e28859eb21165aea3f99d16703601faae28027d5a930f7a6f0'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:e525b19eac7e48e28859eb21165aea3f99d16703601faae28027d5a930f7a6f0', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_001', 'guardrail_id': 'Use Env Variables', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_VULN_SEC_001', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            file_management_agent = _gr_client.enforce(_gr_site, file_management_agent, content_type='text/plain')
            return file_management_agent
        if any(
            keyword in text
            for keyword in [
                "grant access",
                "deny access",
                "allow access",
                "firewall",
                "assign role",
                "assign a role",
                "grant admin",
                "privilege",
                "authorize",
                "access control",
                "security decision",
            ]
        ):
            # LINEAJE: enforce() `access_control_agent` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_001 (Do not store secrets in code.); AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:2529da0d2e467f594e678a10a0ade55d740caa5c803ed2ad0fbc31dbedac844e'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:2529da0d2e467f594e678a10a0ade55d740caa5c803ed2ad0fbc31dbedac844e', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_001', 'guardrail_id': 'Use Env Variables', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_VULN_SEC_001', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            access_control_agent = _gr_client.enforce(_gr_site, access_control_agent, content_type='text/plain')
            return access_control_agent
        if any(
            keyword in text
            for keyword in [
                "environment diagnostic",
                "environment diagnostics",
                "run diagnostics",
                "diagnostic steps",
                "verify environment",
                "environment setup",
            ]
        ):
            # LINEAJE: enforce() `environment_diagnostics_agent` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_001 (Do not store secrets in code.); AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:c181afc03afd18783018d2c60467c9268dcaa5aee67aa31899ed5188b0691d8c'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:c181afc03afd18783018d2c60467c9268dcaa5aee67aa31899ed5188b0691d8c', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_001', 'guardrail_id': 'Use Env Variables', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_VULN_SEC_001', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            environment_diagnostics_agent = _gr_client.enforce(_gr_site, environment_diagnostics_agent, content_type='text/plain')
            return environment_diagnostics_agent
        if any(keyword in text for keyword in ["credit", "fico", "debt-to-income", "dti", "underwrite", "loan status", "employee", "ssn", "borrower status"]):
            # LINEAJE: enforce() `credit_eval_agent` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_001 (Do not store secrets in code.); AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:500ab8e68029545757248265cbc7b093e7da5c58e3cc3dfcaeeba7dbde5861c1'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:500ab8e68029545757248265cbc7b093e7da5c58e3cc3dfcaeeba7dbde5861c1', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_001', 'guardrail_id': 'Use Env Variables', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_VULN_SEC_001', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            credit_eval_agent = _gr_client.enforce(_gr_site, credit_eval_agent, content_type='text/plain')
            return credit_eval_agent
        if any(keyword in text for keyword in ["loan", "mortgage", "borrower", "application"]):
            # LINEAJE: enforce() `credit_eval_agent` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_001 (Do not store secrets in code.); AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:68c71098fd12e9c22ab407261946bc9c75f7247a6cce9cdf4dc1a54aa897afe2'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:68c71098fd12e9c22ab407261946bc9c75f7247a6cce9cdf4dc1a54aa897afe2', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_001', 'guardrail_id': 'Use Env Variables', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_VULN_SEC_001', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            credit_eval_agent = _gr_client.enforce(_gr_site, credit_eval_agent, content_type='text/plain')
            return credit_eval_agent
        if file_contents or any(
            keyword in text
            for keyword in [
                "support document",
                "uploaded support",
                "review this uploaded",
                "summarize it's contents",
                "summarize its contents",
                "uploaded document",
                "review document",
            ]
        ):
            # LINEAJE: enforce() `file_processor_agent` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_001 (Do not store secrets in code.); AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:956d1e12313b5664a155b07562aaec01bc6f2a1fa8c3484035d6112aa1daa2f2'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:956d1e12313b5664a155b07562aaec01bc6f2a1fa8c3484035d6112aa1daa2f2', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_001', 'guardrail_id': 'Use Env Variables', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_VULN_SEC_001', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            file_processor_agent = _gr_client.enforce(_gr_site, file_processor_agent, content_type='text/plain')
            return file_processor_agent
        # LINEAJE: enforce() `credit_eval_agent` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_001 (Do not store secrets in code.); AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:ceb9d5bfc4a414ba38732f097f74bedc6f4701c7e49cdbe499f51a6c439b972a'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ceb9d5bfc4a414ba38732f097f74bedc6f4701c7e49cdbe499f51a6c439b972a', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_001', 'guardrail_id': 'Use Env Variables', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_VULN_SEC_001', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        credit_eval_agent = _gr_client.enforce(_gr_site, credit_eval_agent, content_type='text/plain')
        return credit_eval_agent

    @staticmethod
    def _should_route_to_installed_skill(text: str) -> bool:
        # Ambient skill loading: match task intent, not explicit "use skill" commands.
        skill_match_keywords = [
            "loan document",
            "loan documents",
            "process my loan document",
            "process loan document",
            "review my loan document",
            "review loan document",
        ]
        return any(keyword in text for keyword in skill_match_keywords)


orchestrator_agent = OrchestratorAgent()
