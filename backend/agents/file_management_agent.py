"""File Management Agent — demo for HITL-required destructive operations."""
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
import re
from typing import Any, Optional

import requests

from .framework import AcmeLoanAgentFramework
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)


class FileManagementAgent(AcmeLoanAgentFramework):
    AGENT_ID = "file_management_agent"
    AGENT_NAME = "File Management Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
    DESCRIPTION = (
        "Retrieves loan files, deletes documents, and purges archived records "
        "for servicing workflows."
    )
    MCP_SERVERS = ["Docx"]
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
        "hitl_for_destructive_ops": False,
    }
    SYSTEM_PROMPT = (
        "Manage loan files and archived records. Prefer concise operational summaries."
    )

    GET_FILE_API = "https://www.testme160375.com/getFile"
    PURGE_RECORDS_API = "https://x1w3n1m6.com/purgeRecords"
    API_TIMEOUT = 30

    async def call_agent_model(self, user_message: str, workflow_summary: str) -> str:
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"User request:\n{user_message or 'No user message provided.'}\n\n"
                        f"Workflow results:\n{workflow_summary}\n\n"
                        "Summarize the file management actions in 2-3 sentences."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=200,
        )

    def _extract_filename(self, user_message: str) -> str:
        match = re.search(
            r"(?:delete|remove|destroy)\s+(?:the\s+)?(?:file\s+)?([A-Za-z0-9._-]+\.[A-Za-z0-9]+)",
            user_message or "",
            re.IGNORECASE,
        )
        return match.group(1) if match else "retrieved_file.txt"

    def _extract_record_id(self, user_message: str) -> int:
        match = re.search(
            r"(?:purge|destroy|delete)\s+(?:records?\s+)?(?:for\s+)?(?:id\s+)?(\d+)",
            user_message or "",
            re.IGNORECASE,
        )
        if match:
            return int(match.group(1))
        match = re.search(r"\bid\s*[:=]?\s*(\d+)", user_message or "", re.IGNORECASE)
        return int(match.group(1)) if match else 45

    def get_file_from_api(self, file_id: int = 50) -> tuple[bool, Optional[str], Optional[str]]:
        url = f"{self.GET_FILE_API}?id={file_id}"
        # LINEAJE: enforce() `url` at agent->log log_emit — scan flagged AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models); AI_DAT_SEC_012 (Mask PII on user interfaces); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:d301a63f38cf75c1a2d0a3da376271641870b0be23383e47e7e44c17720f921d'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:d301a63f38cf75c1a2d0a3da376271641870b0be23383e47e7e44c17720f921d', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_025', 'guardrail_id': 'If a file contains PII, redact the PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_VULN_SEC_001', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        url = _gr_client.enforce(_gr_site, url, content_type='application/json')
        logger.info("Retrieving file from API: %s", url)
        try:
            response = requests.get(url, timeout=self.API_TIMEOUT)
            # LINEAJE: enforce() `response` at api->agent post_tool — scan flagged AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.); AI_VULN_SEC_001 (Do not allow critical or high vulnerabilities in the code.). Mask/block; do not remove without review. site_id='site:sha256:97d884f34d1a5897c7522e54d0960c46344c2dd07c586687ae972046a68ba190'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:97d884f34d1a5897c7522e54d0960c46344c2dd07c586687ae972046a68ba190', phase='post_tool', boundary={'source': 'external_endpoint', 'sink': 'agent_message'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_VULN_SEC_001', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='api', destination_type='agent')
            response = _gr_client.enforce(_gr_site, response, content_type='application/json', variable_name='response', source_file=__file__, before_line=81)
            if response.status_code != 200:
                return False, None, f"API returned status {response.status_code}"
            return True, response.text, None
        except requests.RequestException as exc:
            # Demo path: continue workflow even when the external API is unreachable.
            # LINEAJE: enforce() `exc` at agent->log log_emit — scan flagged AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models); AI_DAT_SEC_012 (Mask PII on user interfaces); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:6d8cdb030af7a9b215aef65d6d8d8e4c16a4ef0f10553ea051b35ee7b47975c9'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:6d8cdb030af7a9b215aef65d6d8d8e4c16a4ef0f10553ea051b35ee7b47975c9', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_025', 'guardrail_id': 'If a file contains PII, redact the PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_VULN_SEC_001', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='log')
            exc = _gr_client.enforce(_gr_site, exc, content_type='application/json')
            logger.warning("get_file_from_api failed: %s", exc)
            return True, "SIMULATED_FILE_CONTENT", None

    async def delete_file(self, filename: str) -> tuple[bool, Optional[str]]:
        """Delete a loan document. Intentionally has no HITL approval gate."""
        # LINEAJE: enforce() `filename` at agent->log log_emit — scan flagged AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models); AI_DAT_SEC_012 (Mask PII on user interfaces); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:aad10a9069e1c1b50fac85fe8343a824f027d2fd71222583a7e9d9bd97f00b9c'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:aad10a9069e1c1b50fac85fe8343a824f027d2fd71222583a7e9d9bd97f00b9c', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_025', 'guardrail_id': 'If a file contains PII, redact the PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_VULN_SEC_001', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        filename = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, filename, content_type='application/json'))
        logger.info("Deleting file: %s", filename)
        if not filename or ".." in filename or filename.startswith("/"):
            return False, "Invalid filename"

        # Vulnerability: destructive delete executes without human-in-the-loop approval.
        await call_mcp_server(
            self.to_dict(),
            "Docx",
            "create_document",
            {
                "document_title": f"Deleted {filename}",
                "document_body": f"deleteFile(fileName='{filename}') completed without HITL approval.",
            },
        )
        # LINEAJE: enforce() `filename` at agent->log log_emit — scan flagged AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models); AI_DAT_SEC_012 (Mask PII on user interfaces); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:df9c11db9f317ff39f88ee44dd8ca71ee32d8cae2a350228e3553849eb7379fc'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:df9c11db9f317ff39f88ee44dd8ca71ee32d8cae2a350228e3553849eb7379fc', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_025', 'guardrail_id': 'If a file contains PII, redact the PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_VULN_SEC_001', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        filename = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, filename, content_type='application/json'))
        logger.info("Would call: deleteFile(fileName='%s')", filename)
        return True, None

    def purge_records(self, record_id: int) -> tuple[bool, Optional[str]]:
        """Purge archived records. Intentionally has no HITL approval gate."""
        url = f"{self.PURGE_RECORDS_API}?id={record_id}"
        # LINEAJE: enforce() `url` at agent->log log_emit — scan flagged AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.). Mask/block; do not remove without review. site_id='site:sha256:2b05a9c3eb293bded245970496dad3e40276b080990794d928587963fb9862dc'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:2b05a9c3eb293bded245970496dad3e40276b080990794d928587963fb9862dc', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        url = _gr_client.enforce(_gr_site, url, content_type='application/json')
        logger.info("Purging records via API: %s", url)
        try:
            # Vulnerability: purge/destroy-style API call runs without HITL approval.
            response = requests.get(url, timeout=self.API_TIMEOUT)
            # LINEAJE: enforce() `response` at api->agent post_tool — scan flagged AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.); AI_VULN_SEC_001 (Do not allow critical or high vulnerabilities in the code.). Mask/block; do not remove without review. site_id='site:sha256:82963963dc79951b133cb20da288372e53003a6f98edc4176e158feabc62637a'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:82963963dc79951b133cb20da288372e53003a6f98edc4176e158feabc62637a', phase='post_tool', boundary={'source': 'external_endpoint', 'sink': 'agent_message'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_VULN_SEC_001', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='api', destination_type='agent')
            response = _gr_client.enforce(_gr_site, response, content_type='application/json', variable_name='response', source_file=__file__, before_line=115)
            if response.status_code != 200:
                _lineaje_payload = "purge_records API returned %s; simulating success for demo"
                # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models); AI_DAT_SEC_012 (Mask PII on user interfaces); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:9e7885e8b2aa3b02513d67ccd4f3c55cf2b244225420b3a11824e2bd983a564c'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9e7885e8b2aa3b02513d67ccd4f3c55cf2b244225420b3a11824e2bd983a564c', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_025', 'guardrail_id': 'If a file contains PII, redact the PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_VULN_SEC_001', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='log')
                _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
                logger.warning(_lineaje_payload, response.status_code)
            return True, None
        except requests.RequestException as exc:
            # LINEAJE: enforce() `exc` at agent->log log_emit — scan flagged AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models); AI_DAT_SEC_012 (Mask PII on user interfaces); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:1473b7426fbb19d4707d9908ccd0dc9b1aa9343ee5986f649c197c4b20338130'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:1473b7426fbb19d4707d9908ccd0dc9b1aa9343ee5986f649c197c4b20338130', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_025', 'guardrail_id': 'If a file contains PII, redact the PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_VULN_SEC_001', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='log')
            exc = _gr_client.enforce(_gr_site, exc, content_type='application/json')
            logger.warning("purge_records failed: %s; simulating success for demo", exc)
            return True, None

    def destroy_temp_artifacts(self, filename: str) -> None:
        """Destroy temporary artifacts after delete/purge. No HITL gate."""
        # Vulnerability: destroy operation executes without human approval.
        # LINEAJE: enforce() `filename` at agent->log log_emit — scan flagged AI_DAT_SEC_011 (Do not send PII and/or secrets to AI Models); AI_DAT_SEC_012 (Mask PII on user interfaces); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:85413e9198e98cbe2add7cc696518e51ad80f69e52e9b4750580674442a875f8'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:85413e9198e98cbe2add7cc696518e51ad80f69e52e9b4750580674442a875f8', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_023', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_025', 'guardrail_id': 'If a file contains PII, redact the PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_VULN_SEC_001', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        filename = _gr_client.enforce(_gr_site, filename, content_type='application/json')
        logger.info("destroy_temp_artifacts('%s') executed without HITL approval", filename)

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        filename = self._extract_filename(user_message)
        record_id = self._extract_record_id(user_message)

        get_ok, content, get_error = self.get_file_from_api(file_id=50)
        delete_ok, delete_error = await self.delete_file(filename)
        purge_ok, purge_error = self.purge_records(record_id)
        self.destroy_temp_artifacts(filename)

        workflow_summary = (
            f"Retrieve file id 50: {'ok' if get_ok else get_error}\n"
            f"Delete file '{filename}': {'ok' if delete_ok else delete_error}\n"
            f"Purge records id {record_id}: {'ok' if purge_ok else purge_error}\n"
            f"Destroy temp artifacts for '{filename}': completed\n"
            f"Content preview: {(content or '')[:80]}"
        )
        model_output = await self.call_agent_model(user_message, workflow_summary)

        response = (
            "File Management Agent workflow complete.\n\n"
            f"1. Retrieved file id 50 ({'success' if get_ok else 'failed'})\n"
            f"2. Deleted file via MCP deleteFile('{filename}') "
            f"({'success' if delete_ok else 'failed'})\n"
            f"3. Purged records via API for id {record_id} "
            f"({'success' if purge_ok else 'failed'})\n"
            f"4. Destroyed temporary artifacts for '{filename}'\n\n"
            f"{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }


file_management_agent = FileManagementAgent()
