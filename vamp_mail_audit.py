#!/usr/bin/env python3
"""
vamp_mail_audit.py — Auditor de seguridad de correo electrónico
================================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v1.0

DESCRIPCIÓN GENERAL
-------------------
Auditor profesional de la configuración de seguridad del correo electrónico
de un dominio. Comprueba los mecanismos defensivos estándar del ecosistema
de correo: SPF, DKIM, DMARC, registros MX y sondas SMTP activas (STARTTLS,
open relay, banner de versión del MTA).

COMPROBACIONES REALIZADAS
--------------------------
  SPF (Sender Policy Framework — RFC 7208)
    · Presencia del registro TXT en el dominio
    · Registros duplicados (violación RFC 7208 §3.2)
    · Mecanismo +all o ?all: cualquier host puede enviar correo del dominio
    · Mecanismo ~all (softfail): no rechaza, solo marca
    · Más de 10 consultas DNS anidadas (límite RFC 7208 §4.6.4)

  DMARC (Domain-based Message Authentication — RFC 7489)
    · Presencia del registro TXT en _dmarc.<dominio>
    · Política p=none (sin aplicación, solo monitorización)
    · Política p=quarantine (cuarentena)
    · Política p=reject (correcta, máxima protección)
    · pct < 100 (aplicación parcial de la política)
    · Ausencia de rua (sin informes agregados)

  DKIM (DomainKeys Identified Mail — RFC 6376)
    · Búsqueda de selectores habituales (15 selectores)
    · Longitud de clave < 1024 bits (insegura)
    · Longitud de clave de 1024 bits (subóptima)
    · Longitud de clave >= 2048 bits (correcta)
    · Selector con p= vacío (clave revocada)

  Registros MX
    · Presencia de al menos un registro MX

  Sondas SMTP activas (puerto 25, hasta 2 servidores MX)
    · Disponibilidad de STARTTLS (cifrado en tránsito)
    · Test de open relay: MAIL FROM + RCPT TO externos
    · Banner de bienvenida: ¿revela software y versión del MTA?

FORMATOS DE SALIDA
------------------
  Consola  · Rich con tablas y paneles de remediación por severidad
  JSON     · --json FILE    (estructura completa con hallazgos y evidencias)
  HTML     · --html FILE    (informe dark-theme standalone autónomo)
  Cliente  · --report-html / --report-pdf (informe unificado VSL)

CÓDIGO DE SALIDA
----------------
  0 — Sin hallazgos CRITICAL ni HIGH
  1 — Al menos un hallazgo HIGH
  2 — Al menos un hallazgo CRITICAL

DEPENDENCIAS
------------
  dnspython >= 2.4.0
  rich      >= 13.7.0

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import smtplib
import socket
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import List, Optional

import dns.exception
import dns.resolver
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

VERSION   = "1.0"
TOOL_NAME = "vamp-mail-audit"

console = Console()

BANNER = r"""
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___ 
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-mail-audit v1.0 · Email Security Auditor
  ────────────────────────────────────────────────────────────────────────
  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

# ---------------------------------------------------------------------------
# Constantes y tablas de clasificación
# ---------------------------------------------------------------------------

SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3,
    "INFO":     4,
}

SEVERITY_COLOR: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold magenta",
    "LOW":      "cyan",
    "INFO":     "green",
}

# Selectores DKIM habituales que se prueban durante la auditoría
DKIM_SELECTORS: list[str] = [
    "default", "google", "mail", "dkim", "k1", "k2", "s1", "s2",
    "selector1", "selector2", "mandrill", "mailjet", "sendgrid",
    "amazonses", "smtp",
]

# Palabras clave que, combinadas con un número de versión, indican
# que el banner SMTP revela el software del MTA
BANNER_VERSION_KEYWORDS: list[str] = [
    "postfix", "exim", "sendmail", "qmail", "microsoft smtp",
    "exchange", "smtpd", "mdaemon", "hmail server", "mailenable",
    "kerio", "iredmail", "zimbra",
]


# ---------------------------------------------------------------------------
# Estructuras de datos
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """
    Hallazgo de seguridad individual de la auditoría de correo.

    Atributos
    ---------
    severity    : Nivel de riesgo — CRITICAL / HIGH / MEDIUM / LOW / INFO
    category    : Protocolo o componente — SPF / DMARC / DKIM / MX / SMTP
    title       : Título corto del hallazgo
    description : Descripción técnica del problema detectado
    evidence    : Prueba técnica concreta (registro DNS, respuesta SMTP…)
    remediation : Pasos concretos de corrección con ejemplos de configuración
    """

    severity:    str
    category:    str
    title:       str
    description: str
    evidence:    str = ""
    remediation: str = ""

    @property
    def order(self) -> int:
        """Orden numérico de la severidad (menor = más grave)."""
        return SEVERITY_ORDER.get(self.severity, 99)


@dataclass
class MailAuditResult:
    """
    Resultado completo de la auditoría de seguridad de correo de un dominio.

    Atributos
    ---------
    domain               : Dominio auditado
    spf_record           : Primer registro SPF encontrado (None si ausente)
    dmarc_record         : Registro DMARC encontrado (None si ausente)
    dkim_selectors_found : Lista de selectores DKIM con registro válido
    mx_records           : Lista de hosts MX ordenados por prioridad
    findings             : Lista de hallazgos de seguridad detectados
    timestamp            : Marca de tiempo ISO-8601 de la auditoría
    error                : Mensaje de error fatal, si lo hay
    """

    domain:               str
    spf_record:           Optional[str]
    dmarc_record:         Optional[str]
    dkim_selectors_found: List[str]
    mx_records:           List[str]
    findings:             List[Finding]
    timestamp:            str = ""
    error:                Optional[str] = None

    @property
    def max_severity(self) -> str:
        """Severidad máxima (más grave) entre todos los hallazgos."""
        if not self.findings:
            return "INFO"
        return min(self.findings, key=lambda f: f.order).severity


# ---------------------------------------------------------------------------
# Textos de remediación
# ---------------------------------------------------------------------------

_REMED_SPF_ABSENT = (
    "Crear un registro TXT en el DNS del dominio con la política SPF.\n"
    "Ejemplo mínimo con MX propio:\n"
    "  ejemplo.com. IN TXT \"v=spf1 mx -all\"\n"
    "Ejemplo con proveedor de correo externo:\n"
    "  ejemplo.com. IN TXT \"v=spf1 include:_spf.google.com -all\"\n"
    "Herramienta de ayuda: https://www.spf-record.de/\n"
    "Ref: RFC 7208 — Sender Policy Framework"
)

_REMED_SPF_MULTIPLE = (
    "Eliminar todos los registros SPF excepto uno.\n"
    "El RFC 7208 §3.2 prohíbe múltiples registros SPF en el mismo dominio;\n"
    "muchos MTAs tratan el dominio como 'permerror' cuando hay más de uno.\n"
    "Combine todos los mecanismos en un único registro TXT:\n"
    "  ejemplo.com. IN TXT \"v=spf1 include:proveedor1.com ip4:1.2.3.0/24 -all\"\n"
    "Elimine los registros duplicados desde el panel DNS del registrador."
)

_REMED_SPF_ALL_PERMIT = (
    "Cambiar el mecanismo 'all' a '-all' (fallo duro) inmediatamente:\n"
    "  ejemplo.com. IN TXT \"v=spf1 include:proveedor.com -all\"\n"
    "El mecanismo '+all' o '?all' permite que CUALQUIER host de Internet\n"
    "envíe correo como si fuera este dominio, pasando la validación SPF.\n"
    "Esto hace que SPF sea completamente inútil como medida de seguridad.\n"
    "Ref: RFC 7208 §5.1, §5.7"
)

_REMED_SPF_SOFTFAIL = (
    "Considerar cambiar ~all (softfail) a -all (hardfail):\n"
    "  ejemplo.com. IN TXT \"v=spf1 include:proveedor.com -all\"\n"
    "El softfail no rechaza el correo, solo lo etiqueta como sospechoso.\n"
    "Muchos filtros de spam ignoran el softfail y entregan igualmente.\n"
    "Antes de cambiar, compruebe que todos los servidores legítimos están\n"
    "en el registro SPF para evitar falsos positivos."
)

_REMED_SPF_LOOKUPS = (
    "Reducir el número de consultas DNS anidadas a 10 o menos.\n"
    "Cada 'include:', 'a:', 'mx:', 'ptr:', 'exists:' consume una consulta.\n"
    "Técnicas de reducción:\n"
    "  · Sustituir 'include:' por 'ip4:'/'ip6:' donde sea posible\n"
    "  · Consolidar varios includes en un único registro SPF externo\n"
    "  · Usar herramientas de aplanamiento SPF (spf-flatten, dmarcian)\n"
    "  · Eliminar includes de proveedores que ya no se usan\n"
    "Ref: RFC 7208 §4.6.4 — límite de 10 lookups DNS por evaluación"
)

_REMED_DMARC_ABSENT = (
    "Crear un registro DMARC en _dmarc.<dominio>.\n"
    "Fase 1 — Monitorización (sin impacto en el correo):\n"
    "  _dmarc.ejemplo.com. IN TXT \"v=DMARC1; p=none; rua=mailto:dmarc@ejemplo.com\"\n"
    "Fase 2 — Cuarentena (tras analizar los informes durante 2-4 semanas):\n"
    "  _dmarc.ejemplo.com. IN TXT \"v=DMARC1; p=quarantine; pct=100;\"\n"
    "                              \"rua=mailto:dmarc@ejemplo.com\"\n"
    "Fase 3 — Rechazo total (política final recomendada):\n"
    "  _dmarc.ejemplo.com. IN TXT \"v=DMARC1; p=reject; pct=100;\"\n"
    "                              \"rua=mailto:dmarc@ejemplo.com\"\n"
    "Ref: RFC 7489 — Domain-based Message Authentication, Reporting and Conformance"
)

_REMED_DMARC_NONE = (
    "Cambiar la política DMARC de p=none a p=quarantine o p=reject.\n"
    "p=none solo monitoriza, NO protege contra el spoofing del dominio.\n"
    "Proceso de migración recomendado:\n"
    "  1. Analizar los informes rua durante 2-4 semanas\n"
    "  2. Resolver fuentes de correo legítimas que fallen SPF/DKIM\n"
    "  3. Subir a p=quarantine con pct=10, luego pct=50, luego pct=100\n"
    "  4. Finalmente subir a p=reject\n"
    "Ref: RFC 7489 §6.3"
)

_REMED_DMARC_QUARANTINE = (
    "Considerar subir la política DMARC de p=quarantine a p=reject.\n"
    "p=reject rechaza definitivamente el correo que falla DMARC,\n"
    "ofreciendo la protección máxima contra el spoofing del dominio.\n"
    "Compruebe los informes rua antes de cambiar para evitar\n"
    "que correo legítimo sea rechazado.\n"
    "Ref: RFC 7489 §6.3"
)

_REMED_DMARC_PCT = (
    "Subir pct al 100% para aplicar la política DMARC a todo el correo.\n"
    "  _dmarc.ejemplo.com. IN TXT \"v=DMARC1; p=reject; pct=100; ...\"\n"
    "Con pct<100 la política solo se aplica a una fracción del correo,\n"
    "dejando el resto sin protección DMARC efectiva.\n"
    "Ref: RFC 7489 §6.3"
)

_REMED_DMARC_NO_RUA = (
    "Añadir un destino de informes agregados (rua) al registro DMARC.\n"
    "  _dmarc.ejemplo.com. IN TXT \"v=DMARC1; p=reject;\"\n"
    "                              \"rua=mailto:dmarc@ejemplo.com\"\n"
    "Sin rua no recibirá los informes XML diarios que muestran qué fuentes\n"
    "están enviando correo en nombre del dominio (legítimas o fraudulentas).\n"
    "Servicios gratuitos de procesado de informes: dmarcian, postmark.\n"
    "Ref: RFC 7489 §7.2"
)

_REMED_DKIM_ABSENT = (
    "Configurar DKIM en todos los servidores o servicios de envío de correo.\n"
    "Pasos básicos:\n"
    "  1. Generar par de claves RSA de 2048 bits:\n"
    "       openssl genrsa -out dkim_privada.key 2048\n"
    "       openssl rsa -in dkim_privada.key -pubout -out dkim_publica.key\n"
    "  2. Publicar la clave pública en DNS con un selector:\n"
    "       mail._domainkey.ejemplo.com. IN TXT\n"
    "         \"v=DKIM1; k=rsa; p=<clave_pública_base64>\"\n"
    "  3. Configurar el MTA para firmar el correo saliente:\n"
    "       Postfix + OpenDKIM: /etc/opendkim.conf → KeyFile, Selector\n"
    "       Exim: DKIM_DOMAIN, DKIM_SELECTOR, DKIM_PRIVATE_KEY\n"
    "Ref: RFC 6376 — DomainKeys Identified Mail (DKIM)"
)

_REMED_DKIM_KEY_SHORT = (
    "Rotar la clave DKIM a un mínimo de 2048 bits de inmediato:\n"
    "  openssl genrsa -out dkim_nueva.key 2048\n"
    "  openssl rsa -in dkim_nueva.key -pubout -out dkim_publica_nueva.key\n"
    "Publicar el nuevo selector en DNS y actualizar la configuración del MTA.\n"
    "Las claves DKIM menores de 1024 bits pueden ser factorizadas con\n"
    "hardware moderno, permitiendo falsificar las firmas DKIM.\n"
    "Ref: RFC 6376 §3.3.3, BSI TR-02102-2"
)

_REMED_DKIM_KEY_1024 = (
    "Rotar la clave DKIM de 1024 bits a 2048 bits:\n"
    "  openssl genrsa -out dkim_nueva.key 2048\n"
    "  openssl rsa -in dkim_nueva.key -pubout -out dkim_publica.key\n"
    "Proceso de rotación sin interrupción:\n"
    "  1. Generar nuevo par de claves con un nuevo selector (p.ej. 'mail2')\n"
    "  2. Publicar el nuevo selector en DNS\n"
    "  3. Configurar el MTA para usar el nuevo selector\n"
    "  4. Mantener el selector antiguo hasta que expire el TTL del DNS\n"
    "Ref: RFC 8301 — Cryptographic Algorithm and Key Usage in DKIM"
)

_REMED_MX_ABSENT = (
    "Publicar al menos un registro MX para el dominio:\n"
    "  ejemplo.com. IN MX 10 mail.ejemplo.com.\n"
    "  mail.ejemplo.com. IN A 1.2.3.4\n"
    "Sin registros MX el correo dirigido a @ejemplo.com se perderá\n"
    "o será rechazado por los servidores de origen con error 5xx.\n"
    "Si el dominio no debe recibir correo, publique:\n"
    "  ejemplo.com. IN MX 0 .\n"
    "y un SPF -all para indicarlo explícitamente.\n"
    "Ref: RFC 5321 §5, RFC 7505 (dominio sin correo)"
)

_REMED_NO_STARTTLS = (
    "Habilitar STARTTLS en el servidor SMTP (puerto 25).\n"
    "Postfix:\n"
    "  smtpd_tls_security_level = may\n"
    "  smtpd_tls_cert_file = /etc/ssl/certs/cert.pem\n"
    "  smtpd_tls_key_file  = /etc/ssl/private/key.pem\n"
    "  smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1\n"
    "Exim:\n"
    "  tls_certificate = /etc/ssl/certs/cert.pem\n"
    "  tls_privatekey  = /etc/ssl/private/key.pem\n"
    "Sin STARTTLS el correo en tránsito entre servidores circula en claro,\n"
    "expuesto a ataques de intercepción en la red.\n"
    "Ref: RFC 3207 — SMTP STARTTLS Extension"
)

_REMED_OPEN_RELAY = (
    "URGENTE: Deshabilitar el open relay en el servidor SMTP inmediatamente.\n"
    "Postfix:\n"
    "  smtpd_relay_restrictions =\n"
    "    permit_mynetworks\n"
    "    permit_sasl_authenticated\n"
    "    reject_unauth_destination\n"
    "  mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128\n"
    "Exim:\n"
    "  relay_from_hosts = 127.0.0.1 : localhost\n"
    "  relay_to_domains = $primary_hostname\n"
    "Un open relay permite a cualquier host de Internet enviar correo\n"
    "usando este servidor, lo que resulta en inclusión en listas negras\n"
    "(RBL/DNSBL) y posible uso para spam, phishing y BEC.\n"
    "Verificar con: https://mxtoolbox.com/diagnostic.aspx\n"
    "Ref: RFC 5321 §2.1, RFC 6409"
)

_REMED_BANNER_LEAK = (
    "Ocultar la versión del software MTA en el banner SMTP:\n"
    "Postfix:\n"
    "  smtpd_banner = $myhostname ESMTP\n"
    "Exim:\n"
    "  smtp_banner = \"$primary_hostname ESMTP\"\n"
    "Sendmail:\n"
    "  O SmtpGreetingMessage=$j Sendmail; $b\n"
    "Exponer el software y versión exacta del MTA permite a los atacantes\n"
    "identificar CVEs específicos de esa versión y lanzar ataques dirigidos."
)


# ---------------------------------------------------------------------------
# Motor de auditoría
# ---------------------------------------------------------------------------

class MailAuditor:
    """
    Motor principal de auditoría de seguridad de correo electrónico.

    Realiza cinco fases de análisis:
      1. SPF  — Sender Policy Framework (RFC 7208)
      2. DMARC — Domain-based Message Authentication (RFC 7489)
      3. DKIM — DomainKeys Identified Mail (RFC 6376)
      4. MX  — Registros de intercambio de correo
      5. SMTP — Sondas activas: STARTTLS, open relay, banner

    La fase SMTP puede deshabilitarse con no_smtp=True para análisis
    rápido solo basado en DNS (útil cuando el puerto 25 está filtrado
    o cuando se audita un volumen grande de dominios).
    """

    def __init__(self, mx_timeout: int = 10, no_smtp: bool = False) -> None:
        """
        Inicializa el auditor de correo.

        Parámetros
        ----------
        mx_timeout : int  — Timeout en segundos para las sondas SMTP
        no_smtp    : bool — Si True, omite las sondas SMTP activas
        """
        self._timeout = mx_timeout
        self._no_smtp = no_smtp
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout  = 5
        self._resolver.lifetime = 10

    def audit(self, domain: str) -> MailAuditResult:
        """
        Ejecuta la auditoría completa de seguridad de correo para el dominio.

        Parámetros
        ----------
        domain : str — Nombre de dominio a auditar (p.ej. 'ejemplo.com')

        Retorna
        -------
        MailAuditResult — Resultado completo con todos los hallazgos
        """
        findings:             List[Finding] = []
        spf_record:           Optional[str] = None
        dmarc_record:         Optional[str] = None
        dkim_selectors_found: List[str]     = []
        mx_records:           List[str]     = []

        try:
            spf_record           = self._audit_spf(domain, findings)
            dmarc_record         = self._audit_dmarc(domain, findings)
            dkim_selectors_found = self._audit_dkim(domain, findings)
            mx_records           = self._audit_mx(domain, findings)

            if not self._no_smtp and mx_records:
                self._audit_smtp(domain, mx_records, findings)

        except Exception as exc:
            return MailAuditResult(
                domain=domain,
                spf_record=spf_record,
                dmarc_record=dmarc_record,
                dkim_selectors_found=dkim_selectors_found,
                mx_records=mx_records,
                findings=findings,
                timestamp=datetime.now(timezone.utc).isoformat(),
                error=str(exc),
            )

        findings.sort(key=lambda f: f.order)
        return MailAuditResult(
            domain=domain,
            spf_record=spf_record,
            dmarc_record=dmarc_record,
            dkim_selectors_found=dkim_selectors_found,
            mx_records=mx_records,
            findings=findings,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    # ------------------------------------------------------------------ Fase 1: SPF

    def _audit_spf(self, domain: str, findings: List[Finding]) -> Optional[str]:
        """
        Comprueba el registro SPF del dominio.

        Busca registros TXT que comiencen por 'v=spf1', verifica que
        haya exactamente uno, analiza el mecanismo 'all' y cuenta
        el número de consultas DNS anidadas.

        Parámetros
        ----------
        domain   : str          — Dominio a consultar
        findings : List[Finding] — Lista donde añadir los hallazgos

        Retorna
        -------
        str | None — Primer registro SPF encontrado, o None si ausente
        """
        txt_records  = self._query_txt(domain)
        spf_records  = [r for r in txt_records if r.lower().startswith("v=spf1")]

        if not spf_records:
            findings.append(Finding(
                severity="HIGH",
                category="SPF",
                title="Registro SPF ausente",
                description=(
                    f"El dominio {domain} no publica ningún registro SPF. "
                    "Sin SPF cualquier host puede enviar correo haciéndose "
                    "pasar por este dominio sin que los receptores puedan "
                    "detectarlo mediante validación SPF."
                ),
                evidence=f"DNS TXT {domain}: sin registro v=spf1",
                remediation=_REMED_SPF_ABSENT,
            ))
            return None

        if len(spf_records) > 1:
            findings.append(Finding(
                severity="HIGH",
                category="SPF",
                title=f"Múltiples registros SPF ({len(spf_records)}) — violación RFC 7208",
                description=(
                    f"Se encontraron {len(spf_records)} registros SPF para {domain}. "
                    "El RFC 7208 §3.2 prohíbe más de uno; muchos MTAs emiten 'permerror' "
                    "y rechazan o ignoran el correo del dominio al encontrar duplicados."
                ),
                evidence="\n".join(spf_records),
                remediation=_REMED_SPF_MULTIPLE,
            ))

        spf = spf_records[0]
        parts = spf.split()

        # Analizar el mecanismo 'all'
        all_mech: Optional[str] = None
        for part in parts:
            lo = part.lower()
            if lo in ("+all", "?all", "~all", "-all", "all"):
                all_mech = lo
                break

        if all_mech in ("+all", "?all"):
            findings.append(Finding(
                severity="CRITICAL",
                category="SPF",
                title=f"SPF con mecanismo '{all_mech}' — permite cualquier remitente",
                description=(
                    f"El registro SPF del dominio {domain} contiene '{all_mech}', "
                    "lo que significa que CUALQUIER host de Internet puede enviar "
                    "correo como si fuera este dominio y superar la validación SPF. "
                    "Este mecanismo anula por completo la protección ofrecida por SPF "
                    "y facilita el spoofing y el phishing del dominio."
                ),
                evidence=spf,
                remediation=_REMED_SPF_ALL_PERMIT,
            ))
        elif all_mech == "~all":
            findings.append(Finding(
                severity="MEDIUM",
                category="SPF",
                title="SPF con mecanismo '~all' (softfail)",
                description=(
                    f"El registro SPF de {domain} usa '~all' (softfail). "
                    "El correo enviado desde hosts no autorizados se etiqueta "
                    "como sospechoso pero no se rechaza. Muchos filtros de spam "
                    "ignoran el softfail y entregan el correo igualmente."
                ),
                evidence=spf,
                remediation=_REMED_SPF_SOFTFAIL,
            ))
        elif all_mech == "-all":
            findings.append(Finding(
                severity="INFO",
                category="SPF",
                title="SPF con '-all' correcto",
                description=(
                    f"El registro SPF de {domain} rechaza el correo enviado "
                    "desde hosts no autorizados. Configuración correcta."
                ),
                evidence=spf,
            ))

        # Contar consultas DNS anidadas (límite RFC 7208: 10)
        lookup_count = 0
        for part in parts:
            lo = part.lower()
            # Mecanismos que consumen un lookup DNS cada uno
            if (lo.startswith("include:") or lo.startswith("a:")  or
                    lo.startswith("mx:")      or lo.startswith("exists:") or
                    lo == "a" or lo == "mx" or lo == "ptr"):
                lookup_count += 1
            # 'redirect=' también consume un lookup
            if lo.startswith("redirect="):
                lookup_count += 1

        if lookup_count > 10:
            findings.append(Finding(
                severity="MEDIUM",
                category="SPF",
                title=f"SPF supera el límite de 10 consultas DNS ({lookup_count} detectadas)",
                description=(
                    f"El registro SPF de {domain} requiere {lookup_count} consultas "
                    "DNS para ser evaluado. El RFC 7208 §4.6.4 limita a 10 consultas; "
                    "si se supera, el resultado es 'permerror' y el correo puede ser "
                    "rechazado por los servidores receptores."
                ),
                evidence=spf,
                remediation=_REMED_SPF_LOOKUPS,
            ))

        return spf

    # ------------------------------------------------------------------ Fase 2: DMARC

    def _audit_dmarc(self, domain: str, findings: List[Finding]) -> Optional[str]:
        """
        Comprueba el registro DMARC del dominio en _dmarc.<dominio>.

        Analiza la política de aplicación (p=), el porcentaje de correo
        afectado (pct=) y la presencia de un destino de informes (rua=).

        Parámetros
        ----------
        domain   : str          — Dominio a consultar
        findings : List[Finding] — Lista donde añadir los hallazgos

        Retorna
        -------
        str | None — Registro DMARC encontrado, o None si ausente
        """
        dmarc_domain  = f"_dmarc.{domain}"
        txt_records   = self._query_txt(dmarc_domain)
        dmarc_records = [r for r in txt_records if r.lower().startswith("v=dmarc1")]

        if not dmarc_records:
            findings.append(Finding(
                severity="HIGH",
                category="DMARC",
                title="Registro DMARC ausente",
                description=(
                    f"No existe registro DMARC en {dmarc_domain}. Sin DMARC los "
                    "receptores de correo no saben cómo tratar los mensajes que "
                    "fallan la validación SPF/DKIM, facilitando el spoofing y "
                    "el phishing del dominio sin ninguna consecuencia para el atacante."
                ),
                evidence=f"DNS TXT {dmarc_domain}: NXDOMAIN o sin registro v=DMARC1",
                remediation=_REMED_DMARC_ABSENT,
            ))
            return None

        dmarc  = dmarc_records[0]
        tags   = self._parse_dmarc_tags(dmarc)
        policy = tags.get("p", "none").lower()

        if policy == "none":
            findings.append(Finding(
                severity="HIGH",
                category="DMARC",
                title="Política DMARC p=none (solo monitorización, sin protección)",
                description=(
                    f"La política DMARC de {domain} es 'none': solo monitoriza "
                    "el correo pero NO rechaza ni pone en cuarentena los mensajes "
                    "ilegítimos. Un atacante puede suplantar el dominio con total "
                    "impunidad mientras esta política esté vigente."
                ),
                evidence=dmarc,
                remediation=_REMED_DMARC_NONE,
            ))
        elif policy == "quarantine":
            findings.append(Finding(
                severity="MEDIUM",
                category="DMARC",
                title="Política DMARC p=quarantine",
                description=(
                    f"La política DMARC de {domain} envía a cuarentena (spam/junk) "
                    "el correo que falla la validación. Es una buena práctica, pero "
                    "se recomienda migrar a p=reject para máxima protección."
                ),
                evidence=dmarc,
                remediation=_REMED_DMARC_QUARANTINE,
            ))
        elif policy == "reject":
            findings.append(Finding(
                severity="INFO",
                category="DMARC",
                title="Política DMARC p=reject (correcto)",
                description=(
                    f"La política DMARC de {domain} rechaza el correo que no "
                    "supera la validación SPF/DKIM. Es la configuración más protectora."
                ),
                evidence=dmarc,
            ))
        else:
            findings.append(Finding(
                severity="MEDIUM",
                category="DMARC",
                title=f"Política DMARC desconocida o inválida: p={policy}",
                description=(
                    f"El valor de la política DMARC '{policy}' no es estándar. "
                    "Los valores válidos son: none, quarantine, reject. "
                    "Una política inválida puede provocar que DMARC sea ignorado."
                ),
                evidence=dmarc,
                remediation=_REMED_DMARC_NONE,
            ))

        # pct — porcentaje de aplicación
        try:
            pct = int(tags.get("pct", "100"))
        except ValueError:
            pct = 100

        if pct < 100:
            findings.append(Finding(
                severity="LOW",
                category="DMARC",
                title=f"DMARC pct={pct} — política aplicada solo al {pct}% del correo",
                description=(
                    f"La política DMARC de {domain} solo se aplica al {pct}% del "
                    f"correo. El {100 - pct}% restante no está protegido por DMARC, "
                    "lo que puede ser explotado por atacantes que reintenten el envío "
                    "hasta que caigan en el porcentaje no aplicado."
                ),
                evidence=dmarc,
                remediation=_REMED_DMARC_PCT,
            ))

        # rua — destino de informes agregados
        if "rua" not in tags:
            findings.append(Finding(
                severity="LOW",
                category="DMARC",
                title="DMARC sin rua (sin informes de autenticación)",
                description=(
                    f"El registro DMARC de {domain} no incluye 'rua'. Sin este campo "
                    "el dominio no recibirá los informes diarios que muestran qué "
                    "fuentes envían correo en su nombre, dificultando la detección "
                    "de abuso o configuraciones erróneas."
                ),
                evidence=dmarc,
                remediation=_REMED_DMARC_NO_RUA,
            ))

        return dmarc

    def _parse_dmarc_tags(self, record: str) -> dict[str, str]:
        """
        Parsea las etiquetas clave=valor de un registro DMARC.

        Parámetros
        ----------
        record : str — Cadena del registro DMARC (p.ej. 'v=DMARC1; p=reject; pct=100')

        Retorna
        -------
        dict[str, str] — Diccionario con las etiquetas en minúsculas
        """
        tags: dict[str, str] = {}
        for part in record.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                tags[k.strip().lower()] = v.strip()
        return tags

    # ------------------------------------------------------------------ Fase 3: DKIM

    def _audit_dkim(self, domain: str, findings: List[Finding]) -> List[str]:
        """
        Busca registros DKIM para los selectores habituales.

        Para cada selector encontrado, analiza el tamaño de la clave RSA
        decodificando el campo 'p=' en base64.

        Parámetros
        ----------
        domain   : str          — Dominio a consultar
        findings : List[Finding] — Lista donde añadir los hallazgos

        Retorna
        -------
        List[str] — Lista de selectores DKIM con registro válido encontrados
        """
        found: List[str] = []

        for selector in DKIM_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{domain}"
            txt_records = self._query_txt(dkim_domain)

            for record in txt_records:
                # Considerar como DKIM si tiene la etiqueta DKIM o el campo p=
                if "v=dkim1" in record.lower() or "p=" in record.lower():
                    found.append(selector)
                    self._check_dkim_key(selector, record, domain, findings)
                    break  # Un hallazgo por selector

        if not found:
            findings.append(Finding(
                severity="HIGH",
                category="DKIM",
                title="No se encontraron selectores DKIM activos",
                description=(
                    f"No se encontró ningún registro DKIM válido para los "
                    f"{len(DKIM_SELECTORS)} selectores habituales probados en {domain}. "
                    "Sin DKIM los receptores no pueden verificar que el correo fue "
                    "enviado realmente por el dominio, facilitando la falsificación "
                    "de mensajes y el debilitamiento de la validación DMARC."
                ),
                evidence=(
                    f"Selectores probados: {', '.join(DKIM_SELECTORS)}\n"
                    "Ninguno devolvió un registro DKIM válido."
                ),
                remediation=_REMED_DKIM_ABSENT,
            ))

        return found

    def _check_dkim_key(
        self,
        selector: str,
        record:   str,
        domain:   str,
        findings: List[Finding],
    ) -> None:
        """
        Extrae y analiza la clave pública DKIM del campo 'p='.

        Si el campo 'p=' está vacío, el selector ha sido revocado.
        Si contiene un valor base64 válido, estima el tamaño de la clave RSA
        y emite el hallazgo de severidad correspondiente.

        Parámetros
        ----------
        selector : str          — Nombre del selector DKIM
        record   : str          — Contenido del registro TXT DKIM
        domain   : str          — Dominio auditado
        findings : List[Finding] — Lista donde añadir los hallazgos
        """
        # Extraer p=<valor> del registro (los registros TXT pueden tener comillas)
        p_value: Optional[str] = None
        clean_record = record.replace('"', '')
        for part in clean_record.split(";"):
            part = part.strip()
            if part.lower().startswith("p="):
                p_value = part[2:].strip()
                break

        evidence_prefix = f"{selector}._domainkey.{domain}"

        if p_value is None or p_value == "":
            # p= vacío indica clave revocada intencionalmente
            findings.append(Finding(
                severity="INFO",
                category="DKIM",
                title=f"Selector DKIM '{selector}' revocado (p= vacío)",
                description=(
                    f"El selector DKIM '{selector}' tiene el campo p= vacío, lo que "
                    "indica que la clave ha sido revocada intencionalmente. "
                    "Esto es correcto si el selector ya no está en uso activo."
                ),
                evidence=f"{evidence_prefix}: {record[:200]}",
            ))
            return

        # Decodificar base64 y estimar el tamaño de la clave
        try:
            b64_clean  = p_value.replace(" ", "")
            der_bytes  = base64.b64decode(b64_clean)
            key_bits   = self._estimate_rsa_bits(der_bytes)
            short_key  = f"p={b64_clean[:60]}{'…' if len(b64_clean) > 60 else ''}"

            if key_bits > 0 and key_bits < 1024:
                findings.append(Finding(
                    severity="HIGH",
                    category="DKIM",
                    title=f"Clave DKIM insegura en selector '{selector}' ({key_bits} bits)",
                    description=(
                        f"La clave DKIM del selector '{selector}' en {domain} tiene "
                        f"{key_bits} bits, por debajo del mínimo seguro de 1024 bits. "
                        "Claves tan cortas pueden factorizarse con hardware accesible, "
                        "permitiendo falsificar las firmas DKIM del dominio."
                    ),
                    evidence=f"{evidence_prefix}: {short_key}",
                    remediation=_REMED_DKIM_KEY_SHORT,
                ))
            elif 1024 <= key_bits < 2048:
                findings.append(Finding(
                    severity="MEDIUM",
                    category="DKIM",
                    title=f"Clave DKIM de {key_bits} bits en selector '{selector}'",
                    description=(
                        f"La clave DKIM del selector '{selector}' en {domain} tiene "
                        f"{key_bits} bits. Actualmente aceptable según el RFC 6376, "
                        "pero el RFC 8301 recomienda migrar a 2048 bits o más para "
                        "mayor longevidad criptográfica."
                    ),
                    evidence=f"{evidence_prefix}: {short_key}",
                    remediation=_REMED_DKIM_KEY_1024,
                ))
            else:
                bits_str = f"{key_bits} bits" if key_bits > 0 else "tamaño no determinado"
                findings.append(Finding(
                    severity="INFO",
                    category="DKIM",
                    title=f"Clave DKIM correcta en selector '{selector}' ({bits_str})",
                    description=(
                        f"Se encontró una clave DKIM en el selector '{selector}' "
                        f"de {domain}. El tamaño ({bits_str}) cumple con las "
                        "recomendaciones actuales."
                    ),
                    evidence=f"{evidence_prefix}: {short_key}",
                ))

        except Exception:
            # No se pudo decodificar — registrar hallazgo informativo
            findings.append(Finding(
                severity="INFO",
                category="DKIM",
                title=f"Selector DKIM encontrado: '{selector}'",
                description=(
                    f"Se encontró el selector DKIM '{selector}' en {domain} "
                    "pero no fue posible determinar el tamaño de la clave. "
                    "Verifíquelo manualmente con: opendkim-testkey -d {domain} -s {selector}"
                ),
                evidence=f"{evidence_prefix}: {record[:200]}",
            ))

    def _estimate_rsa_bits(self, der_bytes: bytes) -> int:
        """
        Estima el tamaño en bits de la clave RSA a partir de su codificación DER.

        Recorre la estructura ASN.1 buscando el INTEGER de mayor longitud
        (que corresponde al módulo RSA). No requiere dependencias criptográficas
        externas más allá de stdlib.

        Parámetros
        ----------
        der_bytes : bytes — Clave pública RSA codificada en DER/SPKI

        Retorna
        -------
        int — Tamaño estimado en bits (0 si no se puede determinar)
        """
        try:
            max_int_len = 0
            i = 0
            while i < len(der_bytes) - 2:
                tag = der_bytes[i]
                if tag == 0x02:  # INTEGER — puede ser el módulo RSA
                    # Leer la longitud (codificación BER/DER)
                    if der_bytes[i + 1] & 0x80:
                        # Longitud en forma larga
                        nb = der_bytes[i + 1] & 0x7F
                        if i + 1 + nb >= len(der_bytes):
                            break
                        length = int.from_bytes(
                            der_bytes[i + 2: i + 2 + nb], "big"
                        )
                        i += 2 + nb
                    else:
                        # Longitud en forma corta
                        length = der_bytes[i + 1]
                        i += 2

                    max_int_len = max(max_int_len, length)
                    i += length
                else:
                    i += 1

            if max_int_len <= 0:
                return 0

            # El módulo RSA lleva un byte 0x00 de padding de signo positivo
            # Descontar ese byte si está presente
            effective_bytes = max_int_len - 1
            bits = effective_bytes * 8

            # Redondear al múltiplo de 256 más próximo
            rounded = round(bits / 256) * 256
            return rounded if rounded > 0 else bits

        except Exception:
            return 0

    # ------------------------------------------------------------------ Fase 4: MX

    def _audit_mx(self, domain: str, findings: List[Finding]) -> List[str]:
        """
        Enumera los registros MX del dominio.

        Emite un hallazgo HIGH si no hay registros MX e INFO con la
        lista de servidores encontrados en caso contrario.

        Parámetros
        ----------
        domain   : str          — Dominio a consultar
        findings : List[Finding] — Lista donde añadir los hallazgos

        Retorna
        -------
        List[str] — Lista de nombres de host MX ordenados por prioridad
        """
        mx_hosts: List[str] = []

        try:
            answers = self._resolver.resolve(domain, "MX")
            for rdata in sorted(answers, key=lambda r: r.preference):
                mx_hosts.append(str(rdata.exchange).rstrip("."))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.exception.DNSException:
            pass

        if not mx_hosts:
            findings.append(Finding(
                severity="HIGH",
                category="MX",
                title=f"Sin registros MX en {domain}",
                description=(
                    f"El dominio {domain} no tiene registros MX. El correo "
                    "dirigido a este dominio no puede ser entregado y será "
                    "rebotado con un error 5xx por los servidores de origen."
                ),
                evidence=f"DNS MX {domain}: NXDOMAIN o sin respuesta",
                remediation=_REMED_MX_ABSENT,
            ))
        else:
            findings.append(Finding(
                severity="INFO",
                category="MX",
                title=f"Registros MX encontrados ({len(mx_hosts)})",
                description=(
                    f"El dominio {domain} tiene {len(mx_hosts)} servidor(es) MX."
                ),
                evidence="\n".join(mx_hosts),
            ))

        return mx_hosts

    # ------------------------------------------------------------------ Fase 5: SMTP

    def _audit_smtp(
        self,
        domain:    str,
        mx_hosts:  List[str],
        findings:  List[Finding],
    ) -> None:
        """
        Realiza sondas SMTP activas en los primeros servidores MX del dominio.

        Itera sobre los dos primeros servidores MX y para cada uno realiza
        un análisis del banner, detección de STARTTLS y prueba de open relay.

        Parámetros
        ----------
        domain   : str          — Dominio auditado (para contexto)
        mx_hosts : List[str]    — Lista de hosts MX ordenados por prioridad
        findings : List[Finding] — Lista donde añadir los hallazgos
        """
        for mx_host in mx_hosts[:2]:
            try:
                self._probe_smtp(mx_host, domain, findings)
            except Exception as exc:
                findings.append(Finding(
                    severity="INFO",
                    category="SMTP",
                    title=f"Sonda SMTP no completada: {mx_host}:25",
                    description=(
                        f"No se pudo realizar la sonda SMTP completa a {mx_host} "
                        "en el puerto 25. Puede deberse a filtrado de red del "
                        "puerto 25, firewall, o política del ISP."
                    ),
                    evidence=str(exc),
                ))

    def _probe_smtp(
        self,
        mx_host:  str,
        domain:   str,
        findings: List[Finding],
    ) -> None:
        """
        Sonda SMTP completa contra un único servidor MX.

        Conecta al puerto 25, lee el banner, detecta STARTTLS y realiza
        el test de open relay mediante MAIL FROM + RCPT TO externos.

        Parámetros
        ----------
        mx_host  : str          — Host del servidor MX
        domain   : str          — Dominio auditado (para contexto)
        findings : List[Finding] — Lista donde añadir los hallazgos
        """
        smtp = smtplib.SMTP(timeout=self._timeout)

        try:
            smtp.connect(mx_host, 25)
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
            raise RuntimeError(
                f"Puerto 25 inaccesible en {mx_host}: {exc}"
            ) from exc

        # Analizar el banner de bienvenida
        welcome = smtp.getwelcome()
        if welcome:
            banner = welcome.decode(errors="replace").strip()
            banner_lo = banner.lower()
            for keyword in BANNER_VERSION_KEYWORDS:
                if keyword in banner_lo:
                    # Comprobar que hay un número de versión en el banner
                    if re.search(r"\d+\.\d+", banner):
                        findings.append(Finding(
                            severity="LOW",
                            category="SMTP",
                            title=f"Banner SMTP revela versión del MTA: {mx_host}",
                            description=(
                                f"El banner de bienvenida SMTP de {mx_host} incluye "
                                "el nombre y versión del software MTA. Esto permite "
                                "a los atacantes identificar CVEs específicos de esa "
                                "versión y planificar ataques dirigidos."
                            ),
                            evidence=f"Banner: {banner}",
                            remediation=_REMED_BANNER_LEAK,
                        ))
                    break

        # EHLO y detección de STARTTLS
        starttls_available = False
        try:
            smtp.ehlo("vampsecurelabs-probe.invalid")
            esmtp_features = {k.lower(): v for k, v in smtp.esmtp_features.items()}
            starttls_available = "starttls" in esmtp_features

            if starttls_available:
                findings.append(Finding(
                    severity="INFO",
                    category="SMTP",
                    title=f"STARTTLS disponible en {mx_host}",
                    description=(
                        f"El servidor {mx_host} anuncia soporte para STARTTLS. "
                        "El correo en tránsito puede cifrarse mediante TLS."
                    ),
                    evidence=f"EHLO {mx_host}: STARTTLS anunciado en respuesta 250",
                ))
            else:
                findings.append(Finding(
                    severity="MEDIUM",
                    category="SMTP",
                    title=f"STARTTLS no disponible en {mx_host}",
                    description=(
                        f"El servidor {mx_host} no anuncia soporte para STARTTLS "
                        "en la respuesta EHLO. El correo en tránsito puede circular "
                        "sin cifrado, expuesto a ataques de intercepción."
                    ),
                    evidence=f"EHLO {mx_host}: STARTTLS ausente en capacidades ESMTP",
                    remediation=_REMED_NO_STARTTLS,
                ))
        except smtplib.SMTPException:
            pass

        # Test de open relay
        test_addr = "test@vampsecurelabs-test.invalid"
        try:
            # Enviar EHLO con dominio externo para el test de relay
            smtp.ehlo("vampsecurelabs-test.invalid")

            code_from, _msg_from = smtp.docmd("MAIL", f"FROM:<{test_addr}>")

            if code_from == 250:
                # El servidor aceptó el MAIL FROM externo; probar RCPT TO externo
                code_rcpt, msg_rcpt = smtp.docmd("RCPT", f"TO:<{test_addr}>")
                msg_rcpt_str = msg_rcpt.decode(errors="replace").strip()

                if code_rcpt == 250:
                    # Ambos aceptados: open relay confirmado
                    findings.append(Finding(
                        severity="CRITICAL",
                        category="SMTP",
                        title=f"OPEN RELAY confirmado en {mx_host}",
                        description=(
                            f"El servidor SMTP {mx_host} acepta correo con remitente "
                            f"y destinatario externos al dominio. Esto confirma un "
                            f"open relay que puede ser explotado para enviar spam, "
                            f"phishing o correo de extorsión a terceros usando la "
                            f"infraestructura de {domain}, lo que resultará en la "
                            "inclusión del servidor en listas negras (RBL/DNSBL)."
                        ),
                        evidence=(
                            f"MAIL FROM:<{test_addr}> → {code_from} (aceptado)\n"
                            f"RCPT TO:<{test_addr}>   → {code_rcpt} {msg_rcpt_str}"
                        ),
                        remediation=_REMED_OPEN_RELAY,
                    ))
                else:
                    # RCPT TO rechazado: sin open relay
                    findings.append(Finding(
                        severity="INFO",
                        category="SMTP",
                        title=f"Sin open relay en {mx_host}",
                        description=(
                            f"El servidor {mx_host} rechazó el destinatario externo. "
                            "No se detectó open relay."
                        ),
                        evidence=(
                            f"MAIL FROM:<{test_addr}> → {code_from}\n"
                            f"RCPT TO:<{test_addr}>   → {code_rcpt} (rechazado)"
                        ),
                    ))

                # Limpiar la transacción SMTP
                smtp.docmd("RSET")

        except smtplib.SMTPException:
            pass
        finally:
            try:
                smtp.quit()
            except Exception:
                pass

    # ------------------------------------------------------------------ Utilidades DNS

    def _query_txt(self, name: str) -> List[str]:
        """
        Consulta los registros TXT del nombre DNS indicado.

        Concatena los fragmentos (strings) de cada registro TXT, que en
        RFC 1035 pueden estar divididos en múltiples partes dentro de un
        único registro.

        Parámetros
        ----------
        name : str — Nombre DNS a consultar (FQDN)

        Retorna
        -------
        List[str] — Lista de valores TXT; vacía si no hay registros o error
        """
        try:
            answers = self._resolver.resolve(name, "TXT")
            result: List[str] = []
            for rdata in answers:
                txt = "".join(s.decode(errors="replace") for s in rdata.strings)
                result.append(txt)
            return result
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        except dns.exception.DNSException:
            return []


# ---------------------------------------------------------------------------
# Generación de informes
# ---------------------------------------------------------------------------

class Reporter:
    """
    Genera los distintos formatos de salida de la auditoría de correo.

    Formatos soportados:
      · Consola Rich — tablas y paneles de remediación a color
      · JSON         — estructura completa con hallazgos y evidencias
      · HTML         — informe dark-theme standalone autónomo
    """

    def __init__(self, con: Console) -> None:
        self._c = con

    # ---------------------------------------------------------------- Consola Rich

    def print_result(self, result: MailAuditResult) -> None:
        """
        Muestra el resultado de la auditoría de un dominio en la consola.

        Imprime un resumen de los registros DNS encontrados (SPF, DMARC,
        DKIM, MX), seguido de la tabla de hallazgos y paneles de remediación
        para los hallazgos CRITICAL y HIGH.

        Parámetros
        ----------
        result : MailAuditResult — Resultado de la auditoría a mostrar
        """
        self._c.print(f"\n[bold cyan]{'─'*66}[/]")
        self._c.print(f"  [bold]Dominio:[/] [bold white]{result.domain}[/]")

        if result.error:
            self._c.print(f"  [bold red]ERROR FATAL:[/] {result.error}")
            self._c.print(f"[bold cyan]{'─'*66}[/]")
            return

        sev       = result.max_severity
        sev_color = SEVERITY_COLOR.get(sev, "white")
        ts        = result.timestamp[:19].replace("T", " ") + " UTC" if result.timestamp else ""
        self._c.print(
            f"  [bold]Severidad máxima:[/] [{sev_color}]{sev}[/{sev_color}]  "
            f"[dim]{ts}[/]"
        )
        self._c.print(f"[bold cyan]{'─'*66}[/]\n")

        # Resumen de registros DNS
        spf_txt   = result.spf_record   or "[red]AUSENTE[/]"
        dmarc_txt = result.dmarc_record or "[red]AUSENTE[/]"

        if result.spf_record and len(result.spf_record) > 100:
            spf_txt = result.spf_record[:100] + "…"
        if result.dmarc_record and len(result.dmarc_record) > 100:
            dmarc_txt = result.dmarc_record[:100] + "…"

        self._c.print(f"  [bold]SPF:[/]   {spf_txt}")
        self._c.print(f"  [bold]DMARC:[/] {dmarc_txt}")

        if result.dkim_selectors_found:
            self._c.print(
                f"  [bold]DKIM:[/]  [green]{', '.join(result.dkim_selectors_found)}[/]"
            )
        else:
            self._c.print("  [bold]DKIM:[/]  [red]Sin selectores encontrados[/]")

        if result.mx_records:
            mx_display = ", ".join(result.mx_records[:4])
            if len(result.mx_records) > 4:
                mx_display += f" … (+{len(result.mx_records) - 4})"
            self._c.print(f"  [bold]MX:[/]    {mx_display}")
        else:
            self._c.print("  [bold]MX:[/]    [red]Sin registros MX[/]")

        # Tabla de hallazgos (todos los niveles)
        if result.findings:
            self._c.print()
            tbl = Table(
                show_header=True, header_style="bold cyan", box=None, padding=(0, 1)
            )
            tbl.add_column("SEV",       width=10)
            tbl.add_column("Categoría", width=10)
            tbl.add_column("Hallazgo",  min_width=42)
            for f in result.findings:
                color = SEVERITY_COLOR.get(f.severity, "white")
                tbl.add_row(
                    Text(f.severity,   style=color),
                    Text(f.category),
                    Text(f.title),
                )
            self._c.print(tbl)

            # Paneles de remediación para hallazgos CRITICAL y HIGH
            criticos = [
                f for f in result.findings
                if f.severity in ("CRITICAL", "HIGH") and f.remediation
            ]
            if criticos:
                self._c.print(f"\n  [bold cyan]Remediaciones prioritarias:[/]")
                for f in criticos:
                    self._c.print(
                        Panel(
                            f.remediation,
                            title=(
                                f"[{SEVERITY_COLOR[f.severity]}]{f.severity}"
                                f"[/{SEVERITY_COLOR[f.severity]}] — {f.title}"
                            ),
                            border_style="cyan",
                            expand=False,
                        )
                    )
        else:
            self._c.print("\n  [bold green]Sin hallazgos de seguridad detectados[/]")

    def print_summary(self, results: List[MailAuditResult]) -> None:
        """
        Muestra la tabla resumen de todos los dominios auditados.

        Incluye una fila por dominio con iconos de estado para SPF, DMARC,
        DKIM, MX, SMTP y el conteo de hallazgos críticos/altos.

        Parámetros
        ----------
        results : List[MailAuditResult] — Lista de resultados a resumir
        """
        self._c.print("\n")
        tbl = Table(
            title="Resumen — Auditoría de Seguridad de Correo Electrónico",
            header_style="bold cyan",
            show_lines=True,
        )
        tbl.add_column("Dominio",       min_width=28)
        tbl.add_column("SPF",           width=6)
        tbl.add_column("DMARC",         width=7)
        tbl.add_column("DKIM",          width=7)
        tbl.add_column("MX",            width=5)
        tbl.add_column("SMTP",          width=7)
        tbl.add_column("C/H",           width=5)
        tbl.add_column("Severidad máx", width=14)

        for r in results:
            if r.error:
                tbl.add_row(
                    r.domain,
                    "[red]ERR[/]", "[red]ERR[/]", "[red]ERR[/]",
                    "[red]ERR[/]", "—", "—", "[red]ERROR[/]",
                )
                continue

            sev_col = SEVERITY_COLOR.get(r.max_severity, "white")
            spf_s   = "[green]✔[/]" if r.spf_record   else "[red]✗[/]"
            dmarc_s = "[green]✔[/]" if r.dmarc_record else "[red]✗[/]"

            if r.dkim_selectors_found:
                dkim_s = f"[green]{len(r.dkim_selectors_found)}[/]"
            else:
                dkim_s = "[red]✗[/]"

            mx_s = f"[green]{len(r.mx_records)}[/]" if r.mx_records else "[red]✗[/]"

            # Estado SMTP: alarma si hay CRITICAL o MEDIUM en esa categoría
            smtp_issues = sum(
                1 for f in r.findings
                if f.category == "SMTP" and f.severity in ("CRITICAL", "MEDIUM")
            )
            smtp_s = "[red]⚠[/]" if smtp_issues else "[green]✔[/]"

            crit_hi = sum(1 for f in r.findings if f.severity in ("CRITICAL", "HIGH"))
            tbl.add_row(
                f"[bold]{r.domain}[/]",
                spf_s, dmarc_s, dkim_s, mx_s, smtp_s,
                str(crit_hi),
                f"[{sev_col}]{r.max_severity}[/{sev_col}]",
            )
        self._c.print(tbl)

    # ---------------------------------------------------------------- JSON

    def to_json(self, results: List[MailAuditResult]) -> str:
        """
        Serializa los resultados de la auditoría en formato JSON.

        Estructura del JSON:
          tool · version · generated · results[]
            domain · timestamp · error · spf_record · dmarc_record ·
            dkim_selectors_found · mx_records · max_severity · findings[]

        Parámetros
        ----------
        results : List[MailAuditResult] — Lista de resultados a serializar

        Retorna
        -------
        str — Cadena JSON con indentación de 2 espacios
        """
        def _result_dict(r: MailAuditResult) -> dict:
            return {
                "domain":               r.domain,
                "timestamp":            r.timestamp,
                "error":                r.error,
                "spf_record":           r.spf_record,
                "dmarc_record":         r.dmarc_record,
                "dkim_selectors_found": r.dkim_selectors_found,
                "mx_records":           r.mx_records,
                "max_severity":         r.max_severity,
                "findings": [
                    {
                        "severity":    f.severity,
                        "category":    f.category,
                        "title":       f.title,
                        "description": f.description,
                        "evidence":    f.evidence,
                        "remediation": f.remediation,
                    }
                    for f in r.findings
                ],
            }

        return json.dumps(
            {
                "tool":      TOOL_NAME,
                "version":   VERSION,
                "generated": datetime.now(timezone.utc).isoformat(),
                "results":   [_result_dict(r) for r in results],
            },
            indent=2,
            ensure_ascii=False,
        )

    # ---------------------------------------------------------------- HTML

    def to_html(self, results: List[MailAuditResult]) -> str:
        """
        Genera un informe HTML dark-theme standalone autónomo.

        El informe incluye para cada dominio:
          · Banner de dominio con la severidad máxima
          · Resumen de registros DNS (SPF, DMARC, DKIM, MX)
          · Tabla de hallazgos con severidad, categoría y título
          · Desplegables de remediación para cada hallazgo

        Parámetros
        ----------
        results : List[MailAuditResult] — Lista de resultados a renderizar

        Retorna
        -------
        str — Documento HTML completo como cadena UTF-8
        """
        SEV_CSS: dict[str, str] = {
            "CRITICAL": "sev-crit",
            "HIGH":     "sev-high",
            "MEDIUM":   "sev-med",
            "LOW":      "sev-low",
            "INFO":     "sev-info",
        }
        SEV_BADGE_COLOR: dict[str, str] = {
            "CRITICAL": "#ff4444",
            "HIGH":     "#ff8800",
            "MEDIUM":   "#ffcc00",
            "LOW":      "#4488ff",
            "INFO":     "#555",
        }

        blocks: List[str] = []

        for r in results:
            if r.error:
                blocks.append(
                    f'<div class="result-block">'
                    f'<div class="domain-header">'
                    f'<span class="domain-name">{escape(r.domain)}</span>'
                    f'</div>'
                    f'<p class="sev-crit">ERROR: {escape(r.error)}</p>'
                    f'</div>'
                )
                continue

            sev        = r.max_severity
            sev_cls    = SEV_CSS.get(sev, "sev-info")
            badge_col  = SEV_BADGE_COLOR.get(sev, "#555")
            badge_text = "#fff" if sev in ("CRITICAL", "HIGH", "INFO", "LOW") else "#000"
            ts         = r.timestamp[:19].replace("T", " ") + " UTC" if r.timestamp else ""

            # Registros DNS
            def _rec(value: Optional[str], label: str) -> str:
                if not value:
                    return f'<span class="sev-high">AUSENTE</span>'
                safe = escape(value[:150] + ("…" if len(value) > 150 else ""))
                return f'<code>{safe}</code>'

            spf_html   = _rec(r.spf_record,   "SPF")
            dmarc_html = _rec(r.dmarc_record, "DMARC")
            dkim_html  = (
                f'<span class="good">{escape(", ".join(r.dkim_selectors_found))}</span>'
                if r.dkim_selectors_found
                else '<span class="sev-high">Sin selectores encontrados</span>'
            )
            mx_html = (
                escape(", ".join(r.mx_records[:5]))
                + (" …" if len(r.mx_records) > 5 else "")
                if r.mx_records
                else '<span class="sev-high">Sin registros MX</span>'
            )

            # Tabla de hallazgos
            if r.findings:
                rows_f = ""
                for f in r.findings:
                    remed_html = ""
                    if f.remediation:
                        remed_html = (
                            f'<details class="remed">'
                            f'<summary>Ver remediación</summary>'
                            f'<pre>{escape(f.remediation)}</pre>'
                            f'</details>'
                        )
                    ev_html = ""
                    if f.evidence:
                        ev_html = (
                            f'<div class="ev">{escape(f.evidence[:300])}</div>'
                        )
                    rows_f += (
                        f'<tr>'
                        f'<td class="{SEV_CSS.get(f.severity, "")}">'
                        f'{escape(f.severity)}</td>'
                        f'<td>{escape(f.category)}</td>'
                        f'<td>{escape(f.title)}{ev_html}{remed_html}</td>'
                        f'</tr>\n'
                    )
                findings_html = (
                    f'<table class="ft">'
                    f'<thead><tr>'
                    f'<th>Severidad</th><th>Categoría</th>'
                    f'<th>Hallazgo / Evidencia / Remediación</th>'
                    f'</tr></thead>'
                    f'<tbody>{rows_f}</tbody>'
                    f'</table>'
                )
            else:
                findings_html = '<p class="good">Sin hallazgos de seguridad detectados.</p>'

            blocks.append(f"""
            <div class="result-block">
              <div class="domain-header">
                <span class="domain-name">{escape(r.domain)}</span>
                <span class="badge" style="background:{badge_col};color:{badge_text}">{escape(sev)}</span>
                <span class="ts">{escape(ts)}</span>
              </div>
              <div class="dns-grid">
                <div class="dns-row"><span class="dns-lbl">SPF</span><span class="dns-val">{spf_html}</span></div>
                <div class="dns-row"><span class="dns-lbl">DMARC</span><span class="dns-val">{dmarc_html}</span></div>
                <div class="dns-row"><span class="dns-lbl">DKIM</span><span class="dns-val">{dkim_html}</span></div>
                <div class="dns-row"><span class="dns-lbl">MX</span><span class="dns-val">{mx_html}</span></div>
              </div>
              <h3>Hallazgos ({len(r.findings)})</h3>
              {findings_html}
            </div>""")

        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        all_blocks = "\n".join(blocks)

        return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VampSecure Labs — Email Security Audit</title>
<style>
:root {{
  --bg: #0d0d0d; --surface: #141414; --border: #1e1e1e;
  --text: #e0e0e0; --dim: #888; --accent: #9b59b6;
  --crit: #ff4444; --high: #ff8800; --med: #ffcc00;
  --low: #4488ff; --good: #44cc88;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  background: var(--bg); color: var(--text);
  font-family: 'Consolas','Courier New',monospace;
  font-size: 14px; padding: 24px;
}}
header {{
  border-bottom: 1px solid var(--accent);
  padding-bottom: 16px; margin-bottom: 24px;
}}
header h1 {{ color: var(--accent); font-size: 22px; letter-spacing: .1em; }}
header p  {{ color: var(--dim); font-size: 12px; margin-top: 4px; }}
.result-block {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 6px; padding: 20px; margin-bottom: 20px;
}}
.domain-header {{
  display: flex; align-items: center; gap: 12px;
  margin-bottom: 14px; flex-wrap: wrap;
}}
.domain-name {{ font-size: 17px; font-weight: bold; }}
.ts {{ color: var(--dim); font-size: 11px; margin-left: auto; }}
.badge {{
  display: inline-block; padding: 3px 10px; border-radius: 3px;
  font-size: .74em; font-weight: bold; letter-spacing: .3px;
}}
.sev-crit {{ color: var(--crit); }}
.sev-high {{ color: var(--high); }}
.sev-med  {{ color: var(--med);  }}
.sev-low  {{ color: var(--low);  }}
.sev-info {{ color: var(--dim);  }}
.good     {{ color: var(--good); }}
.dns-grid {{
  display: flex; flex-direction: column; gap: 6px;
  margin-bottom: 16px;
  background: var(--bg);
  border-left: 3px solid var(--accent);
  padding: 10px 14px; border-radius: 0 4px 4px 0;
}}
.dns-row  {{ display: flex; gap: 12px; font-size: 13px; flex-wrap: wrap; }}
.dns-lbl  {{
  color: var(--dim); width: 60px; flex-shrink: 0;
  font-size: 10px; text-transform: uppercase;
  letter-spacing: .05em; padding-top: 2px;
}}
.dns-val  {{ flex: 1; word-break: break-all; }}
.result-block h3 {{
  font-size: 12px; color: var(--dim); margin: 14px 0 6px;
  text-transform: uppercase; letter-spacing: .07em;
}}
.ft {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
.ft th {{
  text-align: left; padding: 6px 10px; color: var(--dim);
  border-bottom: 1px solid var(--border);
  font-size: 10px; text-transform: uppercase; letter-spacing: .04em;
}}
.ft td {{
  padding: 7px 10px; border-bottom: 1px solid var(--border);
  vertical-align: top;
}}
.ft tr:last-child td {{ border-bottom: none; }}
.ev {{
  font-size: 11px; color: var(--dim); margin-top: 4px;
  white-space: pre-wrap; word-break: break-all;
}}
details.remed {{ margin-top: 6px; }}
details.remed summary {{ cursor: pointer; color: var(--accent); font-size: 11px; }}
details.remed pre {{
  background: #0a0a0a; border: 1px solid var(--border);
  border-radius: 4px; padding: 10px; font-size: 11px;
  margin-top: 6px; overflow-x: auto; white-space: pre-wrap;
}}
footer {{
  margin-top: 32px; text-align: center;
  color: var(--dim); font-size: 11px;
}}
</style>
</head>
<body>
<header>
  <h1>VampSecure Labs — Email Security Audit</h1>
  <p>{TOOL_NAME} v{VERSION} &nbsp;·&nbsp; {generated} &nbsp;·&nbsp;
     VampSecure Studios &nbsp;·&nbsp;
     Uso exclusivo en auditorías autorizadas</p>
</header>
{all_blocks}
<footer>© VampSecure Studios — VampSecure Labs Security Research Division</footer>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Conversión al formato de informe unificado VampSecure Labs
# ---------------------------------------------------------------------------

def _findings_vsl(results: List[MailAuditResult]) -> list:
    """
    Convierte los hallazgos de la auditoría de correo al formato Finding
    unificado VampSecure Labs para su inclusión en el informe de cliente.

    Se incluyen únicamente hallazgos de severidad MEDIUM, HIGH o CRITICAL.
    Los hallazgos INFO se omiten para mantener el informe ejecutivo enfocado.

    Parámetros
    ----------
    results : List[MailAuditResult] — Lista de resultados de la auditoría

    Retorna
    -------
    List[VSLFinding] — Hallazgos en formato unificado con prefijo MAIL-NNN
    """
    from vampsec_report import Finding as VSLFinding

    SEVERIDADES = {"CRITICAL", "HIGH", "MEDIUM"}
    hallazgos   = []
    n           = 0

    for r in results:
        for f in r.findings:
            if f.severity not in SEVERIDADES:
                continue
            n += 1
            hallazgos.append(VSLFinding(
                id          = f"MAIL-{n:03d}",
                title       = f.title,
                severity    = f.severity,
                description = f.description,
                evidence    = f.evidence or "—",
                affected    = r.domain,
                remediation = (
                    f.remediation
                    or "Consultar las guías de buenas prácticas de correo de BSI/NIST."
                ),
                tags=[
                    "email", "mail-security",
                    f.category.lower(),
                    f.severity.lower(),
                ],
            ))

    return hallazgos


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    """
    Parsea y valida los argumentos de la línea de comandos.

    Configura el parser con todos los argumentos específicos de
    vamp-mail-audit más el grupo de argumentos de informe unificado VSL.

    Retorna
    -------
    argparse.Namespace — Namespace con todos los argumentos procesados
    """
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            f"VampSecure Labs Email Audit v{VERSION} — "
            "Auditor de seguridad SPF/DKIM/DMARC/MX/SMTP"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Ejemplos:
  %(prog)s -d ejemplo.com
  %(prog)s -d ejemplo.com -d otro.com --no-smtp
  %(prog)s -f dominios.txt --json salida.json --html informe.html
  %(prog)s -d ejemplo.com --report-html cliente.html --client "ACME Corp" --engagement "Pentest-2026"
  %(prog)s -d empresa.es --mx-timeout 15 --report-pdf informe.pdf
        """,
    )
    p.add_argument(
        "-d", "--domain",
        metavar="DOMINIO",
        action="append",
        dest="domains",
        default=[],
        help="Dominio a auditar. Puede repetirse para auditar varios: -d dom1.com -d dom2.com",
    )
    p.add_argument(
        "-f", "--file",
        metavar="FICHERO",
        help="Fichero de texto con un dominio por línea (líneas con # se ignoran)",
    )
    p.add_argument(
        "--mx-timeout",
        metavar="SEG",
        type=int,
        default=10,
        help="Timeout en segundos para las conexiones SMTP (default: 10)",
    )
    p.add_argument(
        "--no-smtp",
        action="store_true",
        help="Omitir las sondas SMTP activas (modo solo DNS, más rápido)",
    )
    p.add_argument(
        "--json",
        metavar="FICHERO",
        help="Guardar el resultado completo en formato JSON",
    )
    p.add_argument(
        "--html",
        metavar="FICHERO",
        help="Guardar el informe en HTML dark-theme autónomo",
    )
    p.add_argument(
        "--dkim-selector",
        dest="dkim_selector",
        action="append",
        default=[],
        metavar="SELECTOR",
        help="Selector DKIM adicional a comprobar (repetible). Útil para selectores propios "
             "no habituales, p.ej. --dkim-selector mi2024",
    )

    # Grupo de argumentos del informe unificado VampSecure Labs
    from vampsec_report import add_report_args
    add_report_args(p)

    return p.parse_args()


def _resolve_domains(args: argparse.Namespace) -> List[str]:
    """
    Construye y normaliza la lista de dominios a auditar.

    Combina los dominios especificados con -d/--domain y los leídos
    del fichero indicado con -f/--file. Normaliza eliminando protocolo
    (http://, https://) y rutas residuales.

    Parámetros
    ----------
    args : argparse.Namespace — Argumentos parseados por argparse

    Retorna
    -------
    List[str] — Lista de dominios normalizados y deduplicados
    """
    domains: List[str] = list(args.domains)

    if args.file:
        path = Path(args.file)
        if not path.is_file():
            console.print(
                f"[bold red]ERROR:[/] Fichero no encontrado: {args.file}"
            )
            sys.exit(1)
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                domains.append(line)

    if not domains:
        console.print(
            "[bold red]ERROR:[/] Especifica al menos un dominio con "
            "-d/--domain o un fichero con -f/--file"
        )
        sys.exit(1)

    # Normalizar: quitar protocolo y rutas
    normalized: List[str] = []
    seen:       set[str]  = set()
    for d in domains:
        d = d.lower().strip()
        for prefix in ("https://", "http://"):
            if d.startswith(prefix):
                d = d[len(prefix):]
                break
        d = d.split("/")[0].strip()
        if d and d not in seen:
            seen.add(d)
            normalized.append(d)

    return normalized


def main() -> None:
    """
    Punto de entrada principal de vamp-mail-audit.

    Coordina la inicialización del auditor, la ejecución de las fases
    de análisis para cada dominio, la presentación de resultados en
    consola y la exportación a los formatos de salida solicitados.

    El código de salida refleja la severidad máxima detectada:
      0 — Sin hallazgos CRITICAL ni HIGH
      1 — Al menos un hallazgo HIGH
      2 — Al menos un hallazgo CRITICAL
    """
    console.print(BANNER, style="bold magenta")

    args     = _parse_args()
    # Selectores DKIM adicionales indicados por el usuario (para selectores propios no habituales)
    for _sel in getattr(args, "dkim_selector", []) or []:
        if _sel and _sel not in DKIM_SELECTORS:
            DKIM_SELECTORS.append(_sel)
    domains  = _resolve_domains(args)
    auditor  = MailAuditor(mx_timeout=args.mx_timeout, no_smtp=args.no_smtp)
    reporter = Reporter(console)

    mode = "[yellow]solo DNS[/]" if args.no_smtp else "[cyan]DNS + SMTP activo[/]"
    console.print(
        f"[bold cyan]Auditando {len(domains)} dominio(s) "
        f"· Modo: {mode}[/]\n"
    )

    results: List[MailAuditResult] = []
    for domain in domains:
        with console.status(f"[cyan]Auditando {domain}…[/]", spinner="dots"):
            result = auditor.audit(domain)
        results.append(result)
        reporter.print_result(result)

    reporter.print_summary(results)

    # Exportar ficheros de salida opcionales
    if args.json:
        Path(args.json).write_text(reporter.to_json(results), encoding="utf-8")
        console.print(f"\n[green]✔[/] JSON guardado en [bold]{args.json}[/]")

    if args.html:
        Path(args.html).write_text(reporter.to_html(results), encoding="utf-8")
        console.print(f"[green]✔[/] HTML guardado en [bold]{args.html}[/]")

    # Informe unificado VampSecure Labs (cliente)
    if getattr(args, "report_html", None) or getattr(args, "report_pdf", None):
        from vampsec_report import VampSecReport, meta_from_args
        meta   = meta_from_args(args, tool=TOOL_NAME, version=VERSION)
        report = VampSecReport(meta=meta, findings=_findings_vsl(results))
        if args.report_html:
            report.to_html_client(args.report_html)
            console.print(
                f"[green]✔[/] Informe cliente HTML guardado en [bold]{args.report_html}[/]"
            )
        if args.report_pdf:
            report.to_pdf(args.report_pdf)
            console.print(
                f"[green]✔[/] Informe cliente PDF guardado en [bold]{args.report_pdf}[/]"
            )

    # Determinar el código de salida según la severidad máxima global
    max_sev = "INFO"
    for r in results:
        if SEVERITY_ORDER.get(r.max_severity, 99) < SEVERITY_ORDER.get(max_sev, 99):
            max_sev = r.max_severity

    sys.exit(2 if max_sev == "CRITICAL" else 1 if max_sev == "HIGH" else 0)


if __name__ == "__main__":
    main()
