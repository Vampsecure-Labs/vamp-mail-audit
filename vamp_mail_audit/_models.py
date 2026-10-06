# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_models.py — Constantes, estructuras de datos y textos de remediación.
Sin I/O ni dependencias externas: sólo stdlib.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

# ---------------------------------------------------------------------------
# Versión y nombre de la herramienta
# ---------------------------------------------------------------------------

VERSION   = "1.2.0"
TOOL_NAME = "vamp-mail-audit"

# ---------------------------------------------------------------------------
# Tablas de clasificación de severidad
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

_REMED_BIMI_ABSENT = (
    "Configurar BIMI (Brand Indicators for Message Identification) para mostrar\n"
    "la imagen de marca en los clientes de correo compatibles.\n"
    "Requisitos previos obligatorios:\n"
    "  · DMARC con p=quarantine o p=reject y pct=100\n"
    "  · Logotipo en formato SVG Tiny PS (perfil estricto)\n"
    "Pasos:\n"
    "  1. Preparar el logotipo en SVG Tiny PS y alojarlo en HTTPS:\n"
    "       https://example.com/logo.svg\n"
    "  2. Publicar el registro DNS:\n"
    "       default._bimi.ejemplo.com. IN TXT\n"
    "         \"v=BIMI1; l=https://example.com/logo.svg\"\n"
    "  3. Opcional pero recomendado: obtener un VMC (Mark Verified Certificate)\n"
    "       de una CA acreditada (DigiCert, Entrust) y añadir el tag 'a=':\n"
    "       \"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/logo.pem\"\n"
    "Ref: BIMI Working Group — https://bimigroup.org/\n"
    "     RFC 9399 — Brand Indicators for Message Identification (BIMI)"
)

_REMED_MTA_STS_ABSENT = (
    "Configurar MTA-STS (SMTP MTA Strict Transport Security, RFC 8461) para\n"
    "forzar el uso de TLS en el correo entrante a este dominio.\n"
    "Pasos:\n"
    "  1. Crear el fichero de política en:\n"
    "       https://mta-sts.ejemplo.com/.well-known/mta-sts.txt\n"
    "     Contenido recomendado (modo enforce):\n"
    "       version: STSv1\n"
    "       mode: enforce\n"
    "       mx: mail.ejemplo.com\n"
    "       max_age: 86400\n"
    "  2. Publicar el registro DNS:\n"
    "       _mta-sts.ejemplo.com. IN TXT \"v=STSv1; id=20240101T000000Z\"\n"
    "       (el 'id' debe cambiar cada vez que se actualice la política)\n"
    "  3. Empezar con mode: testing para verificar que no hay falsos positivos;\n"
    "       migrar a mode: enforce tras analizar los informes TLS-RPT.\n"
    "Complementario: configurar TLS-RPT para recibir informes:\n"
    "  _smtp._tls.ejemplo.com. IN TXT \"v=TLSRPTv1; rua=mailto:tls-reports@ejemplo.com\"\n"
    "Ref: RFC 8461 — SMTP MTA Strict Transport Security (MTA-STS)\n"
    "     RFC 8460 — SMTP TLS Reporting"
)

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
