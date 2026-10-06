# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_core.py — Motor de auditoría de seguridad de correo electrónico.
Sin Rich ni consola: solo lógica DNS/SMTP y producción de hallazgos.
"""

from __future__ import annotations

import base64
import re
import smtplib
import socket
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import List, Optional

import dns.exception
import dns.resolver

from ._models import (
    BANNER_VERSION_KEYWORDS,
    DKIM_SELECTORS,
    Finding,
    MailAuditResult,
    TOOL_NAME,
    VERSION,
    _REMED_BANNER_LEAK,
    _REMED_BIMI_ABSENT,
    _REMED_DKIM_ABSENT,
    _REMED_DKIM_KEY_1024,
    _REMED_DKIM_KEY_SHORT,
    _REMED_DMARC_ABSENT,
    _REMED_DMARC_NONE,
    _REMED_DMARC_NO_RUA,
    _REMED_DMARC_PCT,
    _REMED_DMARC_QUARANTINE,
    _REMED_MTA_STS_ABSENT,
    _REMED_MX_ABSENT,
    _REMED_NO_STARTTLS,
    _REMED_OPEN_RELAY,
    _REMED_SPF_ALL_PERMIT,
    _REMED_SPF_ABSENT,
    _REMED_SPF_LOOKUPS,
    _REMED_SPF_MULTIPLE,
    _REMED_SPF_SOFTFAIL,
)


class MailAuditor:
    """
    Motor principal de auditoría de seguridad de correo electrónico.

    Realiza siete fases de análisis:
      1. SPF     — Sender Policy Framework (RFC 7208)
      2. DMARC   — Domain-based Message Authentication (RFC 7489)
      3. DKIM    — DomainKeys Identified Mail (RFC 6376)
      4. MX      — Registros de intercambio de correo
      5. SMTP    — Sondas activas: STARTTLS, open relay, banner
      6. BIMI    — Brand Indicators for Message Identification (RFC 9399)
      7. MTA-STS — SMTP MTA Strict Transport Security (RFC 8461)

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

            self._audit_bimi(domain, findings)
            self._audit_mta_sts(domain, findings)

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

    # ------------------------------------------------------------------ Fase 6: BIMI

    def _audit_bimi(self, domain: str, findings: List[Finding]) -> None:
        """
        Valida el registro BIMI (Brand Indicators for Message Identification).

        Consulta el selector por defecto 'default._bimi.<domain>'. Un registro
        BIMI válido permite mostrar la imagen de marca del remitente en clientes
        de correo compatibles (Gmail, Yahoo Mail, Apple Mail, etc.).

        Parámetros
        ----------
        domain   : str           — Dominio a consultar
        findings : List[Finding] — Lista donde añadir los hallazgos
        """
        bimi_domain  = f"default._bimi.{domain}"
        txt_records  = self._query_txt(bimi_domain)
        # Registro válido: contiene el tag v=BIMI1 (insensible a mayúsculas)
        bimi_records = [r for r in txt_records if "v=bimi1" in r.lower()]

        if not txt_records:
            # Sin ningún registro TXT en el subdominio BIMI
            findings.append(Finding(
                severity="INFO",
                category="BIMI",
                title="BIMI no configurado",
                description=(
                    f"No se encontró registro BIMI en {bimi_domain}. "
                    "Sin BIMI la imagen de marca del remitente no se mostrará "
                    "en los clientes de correo compatibles (Gmail, Yahoo Mail, etc.)."
                ),
                evidence=f"DNS TXT {bimi_domain}: sin registro",
                remediation=_REMED_BIMI_ABSENT,
            ))
            return

        if not bimi_records:
            # Hay registros TXT pero ninguno tiene v=BIMI1
            findings.append(Finding(
                severity="MEDIUM",
                category="BIMI",
                title="Registro BIMI malformado",
                description=(
                    f"Se encontró un registro TXT en {bimi_domain} pero no contiene "
                    "el tag requerido 'v=BIMI1'. El registro no será reconocido por los "
                    "clientes de correo compatibles con BIMI."
                ),
                evidence="\n".join(txt_records),
                remediation=_REMED_BIMI_ABSENT,
            ))
            return

        # Registro BIMI válido encontrado
        bimi = bimi_records[0]
        findings.append(Finding(
            severity="INFO",
            category="BIMI",
            title="BIMI configurado",
            description=(
                f"El dominio {domain} tiene un registro BIMI válido (v=BIMI1). "
                "La imagen de marca del remitente podrá mostrarse en clientes de "
                "correo compatibles."
            ),
            evidence=f"{bimi_domain}: {bimi[:200]}",
        ))

        # Verificar la presencia del tag 'a=' (VMC — Mark Verified Certificate)
        if "a=" in bimi.lower():
            findings.append(Finding(
                severity="INFO",
                category="BIMI",
                title="BIMI con certificado VMC",
                description=(
                    f"El registro BIMI de {domain} incluye el tag 'a=' con un VMC "
                    "(Mark Verified Certificate). Esto garantiza la autenticidad de la "
                    "imagen de marca ante los proveedores de correo que requieren VMC "
                    "para mostrar la insignia verificada."
                ),
                evidence=f"{bimi_domain}: {bimi[:200]}",
            ))

    # ------------------------------------------------------------------ Fase 7: MTA-STS

    def _audit_mta_sts(self, domain: str, findings: List[Finding]) -> None:
        """
        Valida MTA-STS (SMTP MTA Strict Transport Security, RFC 8461).

        Comprueba la presencia del registro DNS TXT en _mta-sts.<domain> y,
        si existe, descarga y analiza la política publicada en la URL canónica
        https://mta-sts.<domain>/.well-known/mta-sts.txt.

        Parámetros
        ----------
        domain   : str           — Dominio a consultar
        findings : List[Finding] — Lista donde añadir los hallazgos
        """
        sts_domain   = f"_mta-sts.{domain}"
        txt_records  = self._query_txt(sts_domain)
        # Registro válido: contiene el tag v=STSv1
        sts_records  = [r for r in txt_records if "v=stsv1" in r.lower()]

        if not sts_records:
            findings.append(Finding(
                severity="INFO",
                category="MTA-STS",
                title="MTA-STS no configurado",
                description=(
                    f"No se encontró registro MTA-STS en {sts_domain}. "
                    "Sin MTA-STS no existe política de TLS forzado para el correo "
                    "entrante: un atacante con acceso a la red puede degradar la "
                    "conexión SMTP a texto claro sin que los servidores de origen lo detecten."
                ),
                evidence=f"DNS TXT {sts_domain}: sin registro v=STSv1",
                remediation=_REMED_MTA_STS_ABSENT,
            ))
            return

        # Registro DNS MTA-STS encontrado — descargar la política HTTP
        policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        try:
            req = urllib.request.Request(
                policy_url,
                headers={"User-Agent": f"{TOOL_NAME}/{VERSION}"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                policy_text = resp.read().decode(errors="replace")
        except (urllib.error.URLError, OSError, Exception):
            # No se puede acceder a la URL de la política
            findings.append(Finding(
                severity="MEDIUM",
                category="MTA-STS",
                title="Registro MTA-STS DNS presente pero política HTTP no accesible",
                description=(
                    f"El registro DNS MTA-STS existe en {sts_domain} pero no se puede "
                    f"acceder a la política en {policy_url}. Sin la política HTTP publicada, "
                    "los servidores de correo no pueden aplicar las restricciones de TLS."
                ),
                evidence=f"DNS TXT {sts_domain}: {sts_records[0][:200]}\nHTTP GET {policy_url}: error",
                remediation=_REMED_MTA_STS_ABSENT,
            ))
            return

        # Analizar el campo 'mode' de la política MTA-STS
        mode = ""
        for line in policy_text.splitlines():
            line = line.strip()
            if line.lower().startswith("mode:"):
                mode = line.split(":", 1)[1].strip().lower()
                break

        evidence_base = (
            f"DNS TXT {sts_domain}: {sts_records[0][:200]}\n"
            f"Política: {policy_url}\n"
            f"{policy_text[:400]}"
        )

        if mode == "enforce":
            findings.append(Finding(
                severity="INFO",
                category="MTA-STS",
                title="MTA-STS en modo enforce (óptimo)",
                description=(
                    f"El dominio {domain} tiene MTA-STS configurado en modo 'enforce'. "
                    "Los servidores de correo origen deben usar TLS para entregar correo "
                    "a este dominio o rechazar el intento de entrega. Configuración óptima."
                ),
                evidence=evidence_base,
            ))
        elif mode == "testing":
            findings.append(Finding(
                severity="LOW",
                category="MTA-STS",
                title="MTA-STS en modo testing (no aplica políticas)",
                description=(
                    f"El dominio {domain} tiene MTA-STS en modo 'testing'. "
                    "En este modo se recopilan informes pero NO se rechaza el correo "
                    "que no cumple la política TLS. El correo entrante sigue sin protección "
                    "efectiva contra ataques de downgrade TLS."
                ),
                evidence=evidence_base,
                remediation=_REMED_MTA_STS_ABSENT,
            ))
        elif mode == "none":
            findings.append(Finding(
                severity="MEDIUM",
                category="MTA-STS",
                title="MTA-STS desactivado (mode: none)",
                description=(
                    f"El dominio {domain} tiene MTA-STS configurado con 'mode: none', "
                    "lo que desactiva explícitamente cualquier exigencia de TLS. "
                    "El registro DNS existe pero la política no protege el correo entrante."
                ),
                evidence=evidence_base,
                remediation=_REMED_MTA_STS_ABSENT,
            ))
        else:
            # Modo no reconocido o política vacía
            findings.append(Finding(
                severity="MEDIUM",
                category="MTA-STS",
                title="Registro MTA-STS DNS presente pero política HTTP no accesible",
                description=(
                    f"El registro DNS MTA-STS existe en {sts_domain} y la política HTTP "
                    f"en {policy_url} es accesible, pero no contiene un campo 'mode' válido. "
                    "La política MTA-STS no será procesada correctamente por los servidores de correo."
                ),
                evidence=evidence_base,
                remediation=_REMED_MTA_STS_ABSENT,
            ))

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
