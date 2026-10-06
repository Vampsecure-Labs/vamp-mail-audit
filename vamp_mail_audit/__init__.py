# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp_mail_audit — Auditor de seguridad de correo electrónico.
Paquete importable: expone la API pública completa.

Uso como librería:
    from vamp_mail_audit import MailAuditor, MailAuditResult, Finding
    auditor = MailAuditor(no_smtp=True)
    result  = auditor.audit("ejemplo.com")

Uso como CLI:
    vamp-mail-audit -d ejemplo.com
"""

from ._models import (
    VERSION,
    TOOL_NAME,
    SEVERITY_ORDER,
    SEVERITY_COLOR,
    DKIM_SELECTORS,
    BANNER_VERSION_KEYWORDS,
    Finding,
    MailAuditResult,
)
from ._core import MailAuditor
from ._report import Reporter, _findings_vsl
from .cli import main

__all__ = [
    "VERSION",
    "TOOL_NAME",
    "SEVERITY_ORDER",
    "SEVERITY_COLOR",
    "DKIM_SELECTORS",
    "BANNER_VERSION_KEYWORDS",
    "Finding",
    "MailAuditResult",
    "MailAuditor",
    "Reporter",
    "_findings_vsl",
    "main",
]
