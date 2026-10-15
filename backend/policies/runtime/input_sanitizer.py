"""
Input Sanitizer

Sanitizes user input before processing.

SECURITY NOTES (for Unifai demo):
- sanitize() is a NO-OP - input passes through unchanged
- No XSS prevention
- No injection prevention
- No encoding normalization
"""
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
from typing import Any

logger = logging.getLogger(__name__)


class InputSanitizer:
    """
    Sanitizes user input before processing.

    VULNERABILITY: All sanitization methods are NO-OPs.
    Input passes through unchanged.

    Should sanitize:
    - HTML/script injection
    - SQL injection patterns
    - Command injection
    - Path traversal
    - Encoding attacks
    """

    def __init__(self):
        pass

    async def sanitize(self, input_data: Any) -> Any:
        """
        Sanitize input data.

        VULNERABILITY: NO-OP - returns input unchanged.
        """
        _lineaje_payload = "Sanitization requested"
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:6d26a430dced60ff5b4e5de2a95c1e37401899e39bbb08c8a734a02e998a17f1'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:6d26a430dced60ff5b4e5de2a95c1e37401899e39bbb08c8a734a02e998a17f1', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'policy_name': 'Do not log PII.', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/policies/runtime/input_sanitizer.py', 'line': 43, 'function': 'InputSanitizer.sanitize'}})
        try:
            _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        logger.debug(
            _lineaje_payload,
            extra={
                "input_type": type(input_data).__name__,
                "input_preview": str(input_data)[:100]
            }
        )

        # VULNERABILITY: No sanitization performed
        # LINEAJE: enforce() `input_data` at agent->user_interface data_egress — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:220e82c2edd935398adf36c49b1058c200222e167cde913c7b88fb61ea7dbb6b'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:220e82c2edd935398adf36c49b1058c200222e167cde913c7b88fb61ea7dbb6b', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/policies/runtime/input_sanitizer.py', 'line': 52, 'function': 'InputSanitizer.sanitize'}})
        try:
            input_data = _gr_client.enforce(_gr_site, input_data, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return input_data

    async def sanitize_for_llm(self, content: str) -> str:
        """
        Sanitize content before sending to LLM.

        VULNERABILITY: Not implemented.
        """
        # LINEAJE: enforce() `content` at agent->user_interface data_egress — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:4078f5a792fea889074f173d26d50568962ad2c3082d2acc59f6fc30fc08b852'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:4078f5a792fea889074f173d26d50568962ad2c3082d2acc59f6fc30fc08b852', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/policies/runtime/input_sanitizer.py', 'line': 60, 'function': 'InputSanitizer.sanitize_for_llm'}})
        try:
            content = _gr_client.enforce(_gr_site, content, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return content

    async def sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename to prevent path traversal.

        VULNERABILITY: Not implemented.
        """
        # LINEAJE: enforce() `filename` at agent->user_interface data_egress — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:6555016ec2d0bca55d9a3f7d7b10719dc474ce622f4d974461a3c569ca1424d6'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:6555016ec2d0bca55d9a3f7d7b10719dc474ce622f4d974461a3c569ca1424d6', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/policies/runtime/input_sanitizer.py', 'line': 68, 'function': 'InputSanitizer.sanitize_filename'}})
        try:
            filename = _gr_client.enforce(_gr_site, filename, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return filename

    async def normalize_encoding(self, content: str) -> str:
        """
        Normalize text encoding to prevent attacks.

        VULNERABILITY: Not implemented.
        """
        # LINEAJE: enforce() `content` at agent->user_interface data_egress — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:d34820c6322699b31dc5f92f6169e4b9fe41f4b84fb2ef45eb177dd7177a8711'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:d34820c6322699b31dc5f92f6169e4b9fe41f4b84fb2ef45eb177dd7177a8711', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='Acme-Loan-5', organization='Root Organization', project_name='acme_loan_5', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_5', 'version': 'main', 'purl': 'pkg:github/anaghatestuser/acme_loan_5@main'}}, 'invocation': {'file': 'backend/policies/runtime/input_sanitizer.py', 'line': 76, 'function': 'InputSanitizer.normalize_encoding'}})
        try:
            content = _gr_client.enforce(_gr_site, content, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return content
