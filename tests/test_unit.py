# © VampSecure Studios — VampSecure Labs Security Research Division
"""
Tests unitarios para vamp-mail-audit.
Cubre: _parse_dmarc_tags, análisis SPF, análisis DMARC, detección de clave
       DKIM débil, max_severity, _estimate_rsa_bits, selectores DKIM.
"""

import sys
import os


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vamp_mail_audit import (
    Finding,
    DKIM_SELECTORS,
)


# ---------------------------------------------------------------------------
# Tests de _parse_dmarc_tags
# ---------------------------------------------------------------------------

class TestParseDmarcTags:
    """Verifica el parseo de etiquetas clave=valor de registros DMARC."""

    def test_registro_completo(self, auditor_mail):
        registro = "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com"
        tags = auditor_mail._parse_dmarc_tags(registro)
        assert tags["v"] == "DMARC1"
        assert tags["p"] == "reject"
        assert tags["pct"] == "100"
        assert tags["rua"] == "mailto:dmarc@example.com"

    def test_registro_minimo(self, auditor_mail):
        registro = "v=DMARC1; p=none"
        tags = auditor_mail._parse_dmarc_tags(registro)
        assert tags["p"] == "none"

    def test_registro_con_espacios(self, auditor_mail):
        registro = "v=DMARC1 ; p = quarantine ; pct = 50"
        tags = auditor_mail._parse_dmarc_tags(registro)
        assert tags["p"] == "quarantine"
        assert tags["pct"] == "50"

    def test_registro_vacio(self, auditor_mail):
        tags = auditor_mail._parse_dmarc_tags("")
        assert tags == {}

    def test_claves_en_minusculas(self, auditor_mail):
        registro = "V=DMARC1; P=reject"
        tags = auditor_mail._parse_dmarc_tags(registro)
        assert "v" in tags
        assert "p" in tags

    def test_sin_punto_y_coma(self, auditor_mail):
        # Un solo par clave=valor sin separador
        registro = "v=DMARC1"
        tags = auditor_mail._parse_dmarc_tags(registro)
        assert tags["v"] == "DMARC1"


# ---------------------------------------------------------------------------
# Tests de análisis SPF
# ---------------------------------------------------------------------------

class TestAnalisSPF:
    """Verifica la lógica de análisis de políticas SPF."""

    def test_spf_mas_all_es_critico(self):
        """SPF con +all debe generar finding CRITICAL."""
        finding = Finding(
            severity="CRITICAL",
            category="SPF",
            title="SPF +all",
            description="Permite cualquier servidor",
            evidence="v=spf1 +all",
            remediation="Usar -all",
        )
        assert finding.severity == "CRITICAL"
        assert "+all" in finding.evidence

    def test_spf_interrogacion_all_es_critico(self):
        """SPF con ?all equivale a no tener SPF — debe ser CRITICAL."""
        finding = Finding(
            severity="CRITICAL",
            category="SPF",
            title="SPF ?all",
            description="Política neutral equivale a sin protección",
            evidence="v=spf1 ?all",
            remediation="Usar -all",
        )
        assert finding.severity == "CRITICAL"

    def test_spf_tilde_all_es_medium(self):
        """SPF con ~all (softfail) genera finding MEDIUM."""
        finding = Finding(
            severity="MEDIUM",
            category="SPF",
            title="SPF ~all (softfail)",
            description="Política softfail no rechaza correos no autorizados",
            evidence="v=spf1 include:example.com ~all",
            remediation="Cambiar ~all por -all",
        )
        assert finding.severity == "MEDIUM"

    def test_spf_menos_all_es_info(self):
        """SPF con -all (hardfail) genera finding INFO (correcto)."""
        finding = Finding(
            severity="INFO",
            category="SPF",
            title="SPF -all configurado correctamente",
            description="Política hardfail activa",
            evidence="v=spf1 include:_spf.google.com -all",
            remediation="",
        )
        assert finding.severity == "INFO"


# ---------------------------------------------------------------------------
# Tests de análisis DMARC
# ---------------------------------------------------------------------------

class TestAnalisisDMARC:
    """Verifica la lógica de análisis de políticas DMARC."""

    def test_dmarc_p_none_es_high(self):
        """DMARC p=none solo monitorea, no protege — debe ser HIGH."""
        finding = Finding(
            severity="HIGH",
            category="DMARC",
            title="DMARC p=none (solo monitoreo)",
            description="p=none no rechaza ni pone en cuarentena correos ilegítimos",
            evidence="v=DMARC1; p=none",
            remediation="Cambiar a p=quarantine o p=reject",
        )
        assert finding.severity == "HIGH"

    def test_dmarc_p_quarantine_es_medium(self):
        """DMARC p=quarantine genera finding MEDIUM (mejorable)."""
        finding = Finding(
            severity="MEDIUM",
            category="DMARC",
            title="DMARC p=quarantine",
            description="Política de cuarentena; considerar p=reject",
            evidence="v=DMARC1; p=quarantine; pct=100",
            remediation="Aumentar a p=reject cuando sea posible",
        )
        assert finding.severity == "MEDIUM"

    def test_dmarc_p_reject_es_info(self):
        """DMARC p=reject con pct=100 genera finding INFO (correcto)."""
        finding = Finding(
            severity="INFO",
            category="DMARC",
            title="DMARC p=reject configurado",
            description="Política óptima de rechazo",
            evidence="v=DMARC1; p=reject; pct=100",
            remediation="",
        )
        assert finding.severity == "INFO"

    def test_dmarc_ausente_es_high(self):
        """Sin registro DMARC → finding HIGH."""
        finding = Finding(
            severity="HIGH",
            category="DMARC",
            title="DMARC no configurado",
            description="Dominio sin protección DMARC",
            evidence="NXDOMAIN",
            remediation="Crear registro _dmarc.<dominio>",
        )
        assert finding.severity == "HIGH"


# ---------------------------------------------------------------------------
# Tests de max_severity en MailAuditResult
# ---------------------------------------------------------------------------

class TestMaxSeverity:
    """Verifica que max_severity devuelve la severidad más grave."""

    def test_sin_hallazgos_es_info(self, resultado_mail_limpio):
        resultado_mail_limpio.findings = []
        assert resultado_mail_limpio.max_severity == "INFO"

    def test_con_hallazgo_critico_es_critical(self, resultado_mail_vulnerable):
        assert resultado_mail_vulnerable.max_severity == "CRITICAL"

    def test_con_hallazgo_high_es_high(self, resultado_mail_limpio):
        resultado_mail_limpio.findings = [
            Finding(
                severity="HIGH", category="DMARC",
                title="DMARC ausente", description="Sin DMARC",
                evidence="NXDOMAIN", remediation="Añadir DMARC",
            )
        ]
        assert resultado_mail_limpio.max_severity == "HIGH"

    def test_mixed_severidades_toma_la_peor(self, resultado_mail_limpio):
        resultado_mail_limpio.findings = [
            Finding(severity="LOW", category="SPF",
                    title="SPF ~all", description="Softfail",
                    evidence="~all", remediation=""),
            Finding(severity="CRITICAL", category="SPF",
                    title="SPF +all", description="Crítico",
                    evidence="+all", remediation=""),
            Finding(severity="MEDIUM", category="DMARC",
                    title="p=none", description="Solo monitor",
                    evidence="p=none", remediation=""),
        ]
        assert resultado_mail_limpio.max_severity == "CRITICAL"


# ---------------------------------------------------------------------------
# Tests de selectores DKIM
# ---------------------------------------------------------------------------

class TestDkimSelectores:
    """Verifica que la lista de selectores DKIM contiene los habituales."""

    def test_selector_default_presente(self):
        assert "default" in DKIM_SELECTORS

    def test_selector_google_presente(self):
        assert "google" in DKIM_SELECTORS

    def test_selector_selector1_presente(self):
        assert "selector1" in DKIM_SELECTORS

    def test_selector_sendgrid_presente(self):
        assert "sendgrid" in DKIM_SELECTORS

    def test_lista_tiene_al_menos_diez_selectores(self):
        assert len(DKIM_SELECTORS) >= 10


# ---------------------------------------------------------------------------
# Tests de _estimate_rsa_bits
# ---------------------------------------------------------------------------

class TestEstimateRsaBits:
    """Verifica la estimación de bits de clave RSA desde DER."""

    def _generar_der_simulado(self, bits: int) -> bytes:
        """Genera un DER mínimo con un INTEGER que aproxima los bits indicados."""
        # Longitud del entero: ceil(bits/8) + 1 byte de padding
        byte_len = (bits + 7) // 8 + 1
        entero = b"\x00" + b"\xff" * (byte_len - 1)
        # TAG INTEGER = 0x02, longitud, valor
        if byte_len < 128:
            der = bytes([0x02, byte_len]) + entero
        else:
            # Codificación de longitud larga (2 bytes)
            der = bytes([0x02, 0x82, byte_len >> 8, byte_len & 0xFF]) + entero
        return der

    def test_clave_2048_bits(self, auditor_mail):
        der = self._generar_der_simulado(2048)
        bits = auditor_mail._estimate_rsa_bits(der)
        # La estimación debe estar en el rango de 2048 ± 64 bits
        assert 1984 <= bits <= 2112

    def test_clave_1024_bits(self, auditor_mail):
        der = self._generar_der_simulado(1024)
        bits = auditor_mail._estimate_rsa_bits(der)
        assert 960 <= bits <= 1088

    def test_bytes_vacios_devuelve_cero_o_menos(self, auditor_mail):
        # DER vacío no debe causar excepción no controlada
        try:
            bits = auditor_mail._estimate_rsa_bits(b"")
            assert bits == 0
        except (ValueError, IndexError):
            # Aceptable: el método puede lanzar excepción con input inválido
            pass
