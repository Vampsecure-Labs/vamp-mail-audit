# © VampSecure Studios — VampSecure Labs Security Research Division
"""
Fixtures compartidos para los tests de vamp-mail-audit.
Proporciona objetos Finding, MailAuditResult y configuraciones DNS simuladas.
"""

import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vamp_mail_audit import Finding, MailAuditResult, MailAuditor


# ---------------------------------------------------------------------------
# Fixtures de Finding para correo
# ---------------------------------------------------------------------------

@pytest.fixture()
def finding_spf_critico():
    """Finding SPF crítico: política +all permite cualquier origen."""
    return Finding(
        severity="CRITICAL",
        category="SPF",
        title="SPF +all — cualquier servidor puede enviar",
        description="La política +all autoriza a todos los servidores a enviar correo",
        evidence="v=spf1 +all",
        remediation="Cambiar a -all y listar los servidores autorizados",
    )


@pytest.fixture()
def finding_dmarc_ausente():
    """Finding DMARC ausente: sin protección contra suplantación."""
    return Finding(
        severity="HIGH",
        category="DMARC",
        title="DMARC no configurado",
        description="No existe registro _dmarc.<dominio> en el DNS",
        evidence="NXDOMAIN",
        remediation="Crear registro DMARC con política p=quarantine o p=reject",
    )


@pytest.fixture()
def finding_dkim_clave_debil():
    """Finding DKIM con clave RSA < 1024 bits."""
    return Finding(
        severity="HIGH",
        category="DKIM",
        title="Clave DKIM RSA débil (< 1024 bits)",
        description="La clave DKIM usa menos de 1024 bits y puede ser comprometida",
        evidence="512 bits",
        remediation="Rotar la clave DKIM a mínimo 2048 bits",
    )


# ---------------------------------------------------------------------------
# Fixtures de MailAuditResult
# ---------------------------------------------------------------------------

@pytest.fixture()
def resultado_mail_limpio():
    """MailAuditResult sin hallazgos de seguridad."""
    return MailAuditResult(
        domain="example.com",
        spf_record="v=spf1 include:_spf.google.com -all",
        dmarc_record="v=DMARC1; p=reject; pct=100",
        dkim_selectors_found=["google"],
        mx_records=["10 mail.example.com"],
        findings=[],
    )


@pytest.fixture()
def resultado_mail_vulnerable():
    """MailAuditResult con múltiples hallazgos críticos."""
    return MailAuditResult(
        domain="vulnerable.com",
        spf_record="v=spf1 +all",
        dmarc_record=None,
        dkim_selectors_found=[],
        mx_records=["10 mail.vulnerable.com"],
        findings=[
            Finding(
                severity="CRITICAL",
                category="SPF",
                title="SPF +all",
                description="Permite cualquier origen",
                evidence="v=spf1 +all",
                remediation="Usar -all",
            ),
            Finding(
                severity="HIGH",
                category="DMARC",
                title="DMARC ausente",
                description="Sin protección DMARC",
                evidence="NXDOMAIN",
                remediation="Configurar DMARC",
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Fixture de instancia de MailAuditor (sin DNS real)
# ---------------------------------------------------------------------------

@pytest.fixture()
def auditor_mail():
    """Instancia de MailAuditor con timeouts mínimos para tests."""
    return MailAuditor(mx_timeout=1, no_smtp=True)
