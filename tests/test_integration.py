# © VampSecure Studios — VampSecure Labs Security Research Division
"""
Tests de integración para vamp-mail-audit.
Mockea dns.resolver para simular distintos escenarios DNS sin red real.
Verifica el comportamiento completo de la auditoría SPF + DMARC.
"""

import sys
import os
from unittest.mock import MagicMock, patch


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vamp_mail_audit import (
    Finding,
    MailAuditResult,
)


# ---------------------------------------------------------------------------
# Helpers para construir respuestas DNS simuladas
# ---------------------------------------------------------------------------

def _dns_respuesta(registros: list):
    """Crea un objeto que simula dns.resolver.Answer con strings TXT."""
    respuesta = []
    for rec in registros:
        rdata = MagicMock()
        # dns.resolver devuelve bytes en cada string TXT
        rdata.strings = [rec.encode("utf-8") if isinstance(rec, str) else rec]
        respuesta.append(rdata)
    return respuesta


def _dns_nxdomain():
    """Lanza NXDOMAIN como haría dnspython."""
    import dns.exception
    try:
        import dns.resolver
        raise dns.resolver.NXDOMAIN
    except ImportError:
        raise Exception("NXDOMAIN")


# ---------------------------------------------------------------------------
# Test 1: SPF con +all → finding CRITICAL
# ---------------------------------------------------------------------------

class TestIntegracionSPF:
    """Integración del análisis SPF con DNS simulado."""

    def test_spf_mas_all_genera_hallazgo_critico(self, auditor_mail):
        """_audit_spf con +all debe generar al menos un finding CRITICAL."""
        findings = []
        spf_record = "v=spf1 +all"

        with patch.object(auditor_mail, "_query_txt", return_value=[spf_record]):
            resultado = auditor_mail._audit_spf("example.com", findings)

        # Debe encontrar el registro
        assert resultado is not None
        # Debe haber un finding CRITICAL por +all
        criticos = [f for f in findings if f.severity == "CRITICAL" and "SPF" in f.category]
        assert len(criticos) >= 1

    def test_spf_ausente_genera_hallazgo_high(self, auditor_mail):
        """Dominio sin SPF debe generar finding HIGH o CRITICAL."""
        findings = []

        with patch.object(auditor_mail, "_query_txt", return_value=[]):
            resultado = auditor_mail._audit_spf("sin-spf.example.com", findings)

        assert resultado is None
        graves = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
        assert len(graves) >= 1

    def test_spf_menos_all_sin_hallazgo_critico(self, auditor_mail):
        """SPF con -all no debe generar findings CRITICAL."""
        findings = []
        spf_record = "v=spf1 include:_spf.google.com -all"

        with patch.object(auditor_mail, "_query_txt", return_value=[spf_record]):
            resultado = auditor_mail._audit_spf("buena.example.com", findings)

        assert resultado is not None
        criticos = [f for f in findings if f.severity == "CRITICAL" and "SPF" in f.category]
        assert len(criticos) == 0


# ---------------------------------------------------------------------------
# Test 2: DMARC con p=none → finding HIGH
# ---------------------------------------------------------------------------

class TestIntegracionDMARC:
    """Integración del análisis DMARC con DNS simulado."""

    def test_dmarc_p_none_genera_hallazgo_high(self, auditor_mail):
        """DMARC p=none debe generar finding HIGH."""
        findings = []
        dmarc_record = "v=DMARC1; p=none; rua=mailto:dmarc@example.com"

        with patch.object(auditor_mail, "_query_txt", return_value=[dmarc_record]):
            auditor_mail._audit_dmarc("example.com", findings)

        high_findings = [f for f in findings if f.severity == "HIGH" and "DMARC" in f.category]
        assert len(high_findings) >= 1

    def test_dmarc_p_reject_sin_hallazgo_high(self, auditor_mail):
        """DMARC p=reject no debe generar findings HIGH o CRITICAL."""
        findings = []
        dmarc_record = "v=DMARC1; p=reject; pct=100"

        with patch.object(auditor_mail, "_query_txt", return_value=[dmarc_record]):
            auditor_mail._audit_dmarc("seguro.example.com", findings)

        graves = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
        assert len(graves) == 0

    def test_dmarc_ausente_genera_hallazgo(self, auditor_mail):
        """Dominio sin DMARC debe generar findings de seguridad."""
        findings = []

        with patch.object(auditor_mail, "_query_txt", return_value=[]):
            auditor_mail._audit_dmarc("sin-dmarc.example.com", findings)

        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# Test 3: max_severity refleja correctamente el estado global
# ---------------------------------------------------------------------------

class TestIntegracionMaxSeverity:
    """Verifica max_severity con distintas combinaciones de findings."""

    def test_solo_info_devuelve_info(self):
        r = MailAuditResult(
            domain="ok.com",
            spf_record="v=spf1 -all",
            dmarc_record="v=DMARC1; p=reject",
            dkim_selectors_found=["default"],
            mx_records=[],
            findings=[
                Finding(severity="INFO", category="SPF",
                        title="SPF OK", description="",
                        evidence="", remediation=""),
            ],
        )
        assert r.max_severity == "INFO"

    def test_critical_gana_sobre_todo(self):
        r = MailAuditResult(
            domain="mal.com",
            spf_record="v=spf1 +all",
            dmarc_record=None,
            dkim_selectors_found=[],
            mx_records=[],
            findings=[
                Finding(severity="LOW", category="MX",
                        title="MX sin PTR", description="",
                        evidence="", remediation=""),
                Finding(severity="CRITICAL", category="SPF",
                        title="SPF +all", description="",
                        evidence="", remediation=""),
                Finding(severity="HIGH", category="DMARC",
                        title="DMARC ausente", description="",
                        evidence="", remediation=""),
            ],
        )
        assert r.max_severity == "CRITICAL"
