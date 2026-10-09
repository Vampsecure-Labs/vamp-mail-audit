<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<h1 align="center">vamp-mail-audit</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white" alt="Python 3.9+"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT"/>
  <img src="https://img.shields.io/badge/VampSecure-Labs-magenta" alt="VampSecure Labs"/>
  <img src="https://github.com/Vampsecure-Labs/vamp-mail-audit/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</p>

**VampSecure Labs · Security Research Division**

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

`vamp-mail-audit` is an email security auditor that evaluates SPF, DKIM, DMARC, MX, and active SMTP posture for one or more domains. It performs DNS-level analysis (lookup counts, policy strictness, record conflicts) plus optional live SMTP probing for STARTTLS availability, open relay conditions, and banner version disclosure. It is the email security counterpart in the VampSecure Labs toolkit, built for both point-in-time assessments and ongoing CI/CD monitoring of domain email hygiene.

### Features

- SPF analysis: presence check (HIGH if absent), duplicate TXT record detection (RFC 7208 §3.2 violation, HIGH), permissive `+all`/`?all` mechanisms (CRITICAL), softfail `~all` (MEDIUM), `-all` pass (INFO), excessive DNS lookup count > 10 (MEDIUM)
- DMARC analysis: presence check (HIGH if absent), `p=none` reporting-only policy (HIGH), `p=quarantine` (MEDIUM), `p=reject` (INFO), partial deployment `pct < 100` (LOW), missing `rua` reporting address (LOW)
- DKIM selector probing across 15 common selectors: `default`, `google`, `mail`, `dkim`, `k1`, `k2`, `s1`, `s2`, `selector1`, `selector2`, `mandrill`, `mailjet`, `sendgrid`, `amazonses`, `smtp`; key size analysis (< 1024 HIGH, 1024–2047 MEDIUM, ≥ 2048 INFO); revoked selector detection (`p=` empty)
- MX record presence check (HIGH if absent)
- Active SMTP probing (optional): STARTTLS detection, open relay test (MAIL FROM + RCPT TO external address), banner version disclosure (LOW)
- Multi-domain batch scanning: `-d/--domain` repeatable, or a domain list file (`-f/--file`)
- SMTP-free mode (`--no-smtp`) for pure DNS assessment in restricted environments
- Export to Console (Rich), JSON, and HTML (dark-theme standalone)

### Requirements

- Python 3.9 or later
- `dnspython >= 2.4`
- `rich >= 13.7.0`
- Optional: `fpdf2 >= 2.7` for `--report-pdf`

### Installation

```bash
pip install vamp-mail-audit
# or with Homebrew:
brew install vampsecure-labs/labs/vamp-mail-audit
```

```bash
git clone https://github.com/Vampsecure-Labs/vamp-mail-audit.git
cd vamp-mail-audit
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Usage

```
python3 vamp_mail_audit.py --help
```

### Examples

```bash
# Audit a single domain
python3 vamp_mail_audit.py -d example.com

# Audit multiple domains in one command
python3 vamp_mail_audit.py -d example.com -d mail.example.org -d partner.io

# Audit a list of domains from file
python3 vamp_mail_audit.py -f domains.txt

# DNS-only mode (skip live SMTP probing)
python3 vamp_mail_audit.py -d example.com --no-smtp

# Custom SMTP timeout for slow MX servers
python3 vamp_mail_audit.py -d example.com --mx-timeout 30

# Export findings to JSON and HTML
python3 vamp_mail_audit.py -d example.com --json results.json --html report.html

# Generate client-ready engagement report
python3 vamp_mail_audit.py -f domains.txt \
    --client "Acme Corp" --engagement "Email Security Review Q3 2026" \
    --auditor "J. Smith" --report-html client_report.html --report-pdf client_report.pdf
```

### CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-d / --domain DOMAIN` | — | Domain to audit (repeatable for batch scans) |
| `-f / --file FILE` | — | Text file with one domain per line (lines starting with `#` ignored) |
| `--mx-timeout N` | 10 | SMTP connection timeout in seconds |
| `--no-smtp` | off | Skip active SMTP probes (DNS analysis only) |
| `--json FILE` | — | Export results to JSON |
| `--html FILE` | — | Export dark-theme HTML report |
| `--client TEXT` | — | Client name for VSL engagement report |
| `--engagement TEXT` | — | Engagement title for VSL engagement report |
| `--auditor TEXT` | — | Auditor name for VSL engagement report |
| `--report-scope TEXT` | — | Scope description for VSL engagement report |
| `--report-html FILE` | — | Export unified VSL client report (HTML) |
| `--report-pdf FILE` | — | Export unified VSL client report (PDF, requires fpdf2) |

### Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Console | (default) | Rich-colored per-domain panels with SPF/DKIM/DMARC/SMTP findings |
| JSON | `--json FILE` | Machine-readable full result set |
| HTML | `--html FILE` | Dark-theme standalone report |
| Client HTML | `--report-html FILE` | Unified VampSecure Labs engagement report |
| Client PDF | `--report-pdf FILE` | PDF version of the VSL client report |

### Exit Codes

| Code | Meaning | CI/CD Behavior |
|------|---------|----------------|
| `0` | No critical or high findings | Pipeline passes |
| `1` | High-severity findings detected | Pipeline fails — review required |
| `2` | Critical-severity findings detected | Pipeline fails — immediate action required |

### Sample Output

```
  vamp-mail-audit v1.2 · auditing example.com
  ──────────────────────────────────────────────────────────────
  [+] DNS lookups complete · SMTP probe: mx1.example.com:25

  ┌─ CRITICAL ──────────────────────────────────────────────────────────┐
  │  MAIL-003  SPF policy ends with +all (accept all)                   │
  │  Record:   v=spf1 include:_spf.example.com +all                     │
  │  Impact:   Any host on the internet can send as @example.com        │
  │  Fix:      Replace +all with -all or ~all                           │
  └─────────────────────────────────────────────────────────────────────┘

  [HIGH]   MAIL-006  DMARC record absent — no enforcement policy
  [HIGH]   MAIL-009  DKIM: no valid selector found (15 selectors probed)
  [HIGH]   MAIL-013  Open relay detected — external RCPT TO accepted
  [MEDIUM] MAIL-007  DMARC p=none (monitoring only, no enforcement)
  [MEDIUM] MAIL-011  DKIM key size 1024 bits on selector 'mail' (< 2048 recommended)
  [LOW]    MAIL-014  SMTP banner discloses software version: Postfix 3.6.4
  [INFO]   MAIL-015  MTA-STS not configured (SMTP traffic not enforced TLS)

  ──────────────────────────────────────────────────
  SPF: FAIL · DKIM: FAIL · DMARC: FAIL
  Overall posture: CRITICAL — immediate remediation required
  Total: 7 findings
```

### Why vamp-mail-audit vs. MxToolbox · mail-tester.com · Hardenize

| Feature | vamp-mail-audit | MxToolbox | mail-tester.com | Hardenize |
|---------|:---------------:|:---------:|:---------------:|:---------:|
| Fully offline / no cloud dependency | ✅ | ❌ | ❌ | ❌ |
| Batch multi-domain scan from file | ✅ | ❌ | ❌ | ✅ |
| Structured JSON + HTML export | ✅ | ❌ (paid) | ❌ | ❌ |
| Client engagement report (PDF + HTML) | ✅ | ❌ | ❌ | ❌ |
| DKIM key-size analysis per selector | ✅ | ✅ | ❌ | ✅ |
| Open relay active test | ✅ | ✅ | ❌ | ❌ |
| CI/CD integration via exit codes | ✅ | ❌ | ❌ | ❌ |
| MTA-STS / DANE / BIMI checks | ✅ | ✅ | ❌ | ✅ |

- **Built for auditors, not for IT admins.** vamp-mail-audit produces a client-ready engagement report (HTML + PDF) with auditor name, client name, and scope — output that goes straight into a pentest deliverable. MxToolbox and mail-tester.com produce web pages with no structured export.
- **Batch scanning with consistent results.** Feed a file with 50 domains and get a single JSON with all findings in one run, suitable for automated monitoring. No web UI, no rate-limit popups.
- **No data leaves your machine.** DNS queries go to your configured resolver; optional SMTP probing connects only to the target MX. MxToolbox and mail-tester.com send your domain to their cloud — not suitable for confidential client assessments.
- **CI/CD native.** Exit codes (`0` / `1` / `2`) integrate with GitHub Actions, GitLab CI, or Jenkins so email posture regressions break the pipeline before they reach production.

### Check Coverage

| Check ID | Description | Standard | Severity |
|----------|-------------|----------|----------|
| MAIL-001 | SPF record absent — domain not protected against email spoofing | RFC 7208 | HIGH |
| MAIL-002 | Duplicate SPF TXT records (RFC 7208 §3.2 violation) | RFC 7208 §3.2 | HIGH |
| MAIL-003 | SPF ends with `+all` or `?all` — any host accepted as sender | RFC 7208 | CRITICAL |
| MAIL-004 | SPF uses `~all` softfail (no rejection of unauthorized senders) | RFC 7208 | MEDIUM |
| MAIL-005 | SPF lookup count exceeds 10 (DNS lookup limit exceeded) | RFC 7208 §4.6.4 | MEDIUM |
| MAIL-006 | DMARC record absent — no policy enforcement for the domain | RFC 7489 | HIGH |
| MAIL-007 | DMARC policy `p=none` (reporting only, zero enforcement) | RFC 7489 | HIGH |
| MAIL-008 | DMARC `pct < 100` (partial policy application) | RFC 7489 | LOW |
| MAIL-009 | DKIM: no valid public key found across 15 common selectors | RFC 6376 | HIGH |
| MAIL-010 | DKIM key size below 1024 bits (cryptographically weak) | RFC 6376 | HIGH |
| MAIL-011 | DKIM key size 1024–2047 bits (below recommended 2048) | RFC 6376 | MEDIUM |
| MAIL-012 | STARTTLS not advertised on port 25 (plaintext SMTP allowed) | RFC 3207 | HIGH |
| MAIL-013 | Open relay: external RCPT TO accepted without authentication | RFC 5321 | CRITICAL |

### Legal Notice

Use exclusively on systems you own or for which you hold explicit written authorization from the domain owner. Active SMTP probing (`--no-smtp` off) performs live connections to target mail servers. VampSecure Studios assumes no liability for unauthorized use.

### Part of VampSecure Labs Toolkit

`vamp-mail-audit` is one tool in the VampSecure Labs security research toolkit. For the full toolkit including the orchestrator that runs all tools in sequence and aggregates findings into a single engagement report, see:

- Portfolio: [github.com/Vampsecure-Labs](https://github.com/Vampsecure-Labs)

### Version History

| Version | Main changes |
|---------|-------------|
| v1.2 | Bilingual README (EN/ES) |
| v1.1 | SPF/DKIM/DMARC/SMTP checks, batch scanning, client engagement report |

---

© VampSecure Studios — VampSecure Labs Security Research Division

---
---

<a name="español"></a>
## 🇪🇸 Español

`vamp-mail-audit` es un auditor de seguridad de correo electrónico que evalúa la postura SPF, DKIM, DMARC, MX y SMTP activo de uno o varios dominios. Realiza análisis a nivel DNS (conteos de lookups, estrictez de políticas, conflictos de registros) más sondeo SMTP live opcional para disponibilidad de STARTTLS, condiciones de open relay y divulgación de versión en banner. Es la contrapartida de seguridad de correo en el toolkit de VampSecure Labs, diseñado tanto para evaluaciones puntuales como para monitorización continua CI/CD de higiene de correo en dominios.

### Características

- Análisis SPF: comprobación de presencia (HIGH si ausente), detección de registros TXT duplicados (violación RFC 7208 §3.2, HIGH), mecanismos permisivos `+all`/`?all` (CRITICAL), softfail `~all` (MEDIUM), `-all` pasa (INFO), conteo excesivo de DNS lookups > 10 (MEDIUM)
- Análisis DMARC: comprobación de presencia (HIGH si ausente), política `p=none` solo de reporte (HIGH), `p=quarantine` (MEDIUM), `p=reject` (INFO), despliegue parcial `pct < 100` (LOW), dirección de reporte `rua` ausente (LOW)
- Sondeo de selectores DKIM en 15 selectores comunes: `default`, `google`, `mail`, `dkim`, `k1`, `k2`, `s1`, `s2`, `selector1`, `selector2`, `mandrill`, `mailjet`, `sendgrid`, `amazonses`, `smtp`; análisis de tamaño de clave (< 1024 HIGH, 1024–2047 MEDIUM, ≥ 2048 INFO); detección de selector revocado (`p=` vacío)
- Comprobación de presencia de registro MX (HIGH si ausente)
- Sondeo SMTP activo (opcional): detección de STARTTLS, prueba de open relay (MAIL FROM + RCPT TO dirección externa), divulgación de versión en banner (LOW)
- Escaneo en lote multi-dominio: `-d/--domain` repetible, o fichero de lista de dominios (`-f/--file`)
- Modo sin SMTP (`--no-smtp`) para evaluación DNS pura en entornos restringidos
- Exportación a Consola (Rich), JSON y HTML (dark-theme standalone)

### Requisitos

- Python 3.9 o superior
- `dnspython >= 2.4`
- `rich >= 13.7.0`
- Opcional: `fpdf2 >= 2.7` para `--report-pdf`

### Instalación

```bash
pip install vamp-mail-audit
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-mail-audit
```

```bash
git clone https://github.com/Vampsecure-Labs/vamp-mail-audit.git
cd vamp-mail-audit
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Uso

```
python3 vamp_mail_audit.py --help
```

### Ejemplos

```bash
# Auditar un único dominio
python3 vamp_mail_audit.py -d example.com

# Auditar múltiples dominios en un comando
python3 vamp_mail_audit.py -d example.com -d mail.example.org -d partner.io

# Auditar una lista de dominios desde fichero
python3 vamp_mail_audit.py -f domains.txt

# Modo solo DNS (sin sondeo SMTP activo)
python3 vamp_mail_audit.py -d example.com --no-smtp

# Timeout SMTP personalizado para servidores MX lentos
python3 vamp_mail_audit.py -d example.com --mx-timeout 30

# Exportar hallazgos a JSON y HTML
python3 vamp_mail_audit.py -d example.com --json results.json --html report.html

# Generar informe de engagement listo para cliente
python3 vamp_mail_audit.py -f domains.txt \
    --client "Acme Corp" --engagement "Revisión de Seguridad Email Q3 2026" \
    --auditor "J. Smith" --report-html informe_cliente.html --report-pdf informe_cliente.pdf
```

### Referencia CLI

| Flag | Por defecto | Descripción |
|------|-------------|-------------|
| `-d / --domain DOMINIO` | — | Dominio a auditar (repetible para escaneos en lote) |
| `-f / --file FICHERO` | — | Fichero de texto con un dominio por línea (líneas con `#` ignoradas) |
| `--mx-timeout N` | 10 | Timeout de conexión SMTP en segundos |
| `--no-smtp` | off | Omitir sondeos SMTP activos (solo análisis DNS) |
| `--json FILE` | — | Exportar resultados a JSON |
| `--html FILE` | — | Exportar informe HTML dark-theme |
| `--client TEXT` | — | Nombre del cliente para informe de engagement VSL |
| `--engagement TEXT` | — | Título del engagement para informe VSL |
| `--auditor TEXT` | — | Nombre del auditor para informe VSL |
| `--report-scope TEXT` | — | Descripción del alcance para informe VSL |
| `--report-html FILE` | — | Exportar informe unificado VSL para cliente (HTML) |
| `--report-pdf FILE` | — | Exportar informe unificado VSL para cliente (PDF, requiere fpdf2) |

### Formatos de salida

| Formato | Flag | Descripción |
|---------|------|-------------|
| Consola | (predeterminado) | Paneles por dominio con colores Rich con hallazgos SPF/DKIM/DMARC/SMTP |
| JSON | `--json FILE` | Conjunto completo de resultados legible por máquina |
| HTML | `--html FILE` | Informe dark-theme standalone |
| HTML cliente | `--report-html FILE` | Informe de engagement unificado VampSecure Labs |
| PDF cliente | `--report-pdf FILE` | Versión PDF del informe de cliente VSL |

### Códigos de salida

| Código | Significado | Comportamiento CI/CD |
|--------|-------------|----------------------|
| `0` | Sin hallazgos críticos o de alta severidad | Pipeline pasa |
| `1` | Hallazgos de alta severidad detectados | Pipeline falla — revisión requerida |
| `2` | Hallazgos de severidad crítica detectados | Pipeline falla — acción inmediata requerida |

### Por qué vamp-mail-audit vs. MxToolbox · mail-tester.com · Hardenize

| Feature | vamp-mail-audit | MxToolbox | mail-tester.com | Hardenize |
|---------|:---------------:|:---------:|:---------------:|:---------:|
| Totalmente offline / sin dependencia de nube | ✅ | ❌ | ❌ | ❌ |
| Escaneo en lote multi-dominio desde fichero | ✅ | ❌ | ❌ | ✅ |
| Exportación JSON + HTML estructurada | ✅ | ❌ (pago) | ❌ | ❌ |
| Informe de engagement para cliente (PDF + HTML) | ✅ | ❌ | ❌ | ❌ |
| Análisis de tamaño de clave DKIM por selector | ✅ | ✅ | ❌ | ✅ |
| Prueba activa de open relay | ✅ | ✅ | ❌ | ❌ |
| Integración CI/CD vía códigos de salida | ✅ | ❌ | ❌ | ❌ |
| Checks MTA-STS / DANE / BIMI | ✅ | ✅ | ❌ | ✅ |

### Cobertura de checks

| Check ID | Descripción | Estándar | Severidad |
|----------|-------------|----------|-----------|
| MAIL-001 | Registro SPF ausente — dominio sin protección contra spoofing de correo | RFC 7208 | HIGH |
| MAIL-002 | Registros TXT SPF duplicados (violación RFC 7208 §3.2) | RFC 7208 §3.2 | HIGH |
| MAIL-003 | SPF termina con `+all` o `?all` — cualquier host aceptado como remitente | RFC 7208 | CRITICAL |
| MAIL-004 | SPF usa softfail `~all` (sin rechazo de remitentes no autorizados) | RFC 7208 | MEDIUM |
| MAIL-005 | Conteo de lookups SPF superior a 10 (límite de DNS lookups excedido) | RFC 7208 §4.6.4 | MEDIUM |
| MAIL-006 | Registro DMARC ausente — sin aplicación de política para el dominio | RFC 7489 | HIGH |
| MAIL-007 | Política DMARC `p=none` (solo reporte, sin aplicación) | RFC 7489 | HIGH |
| MAIL-008 | DMARC `pct < 100` (aplicación parcial de política) | RFC 7489 | LOW |
| MAIL-009 | DKIM: sin clave pública válida encontrada en 15 selectores comunes | RFC 6376 | HIGH |
| MAIL-010 | Tamaño de clave DKIM inferior a 1024 bits (criptográficamente débil) | RFC 6376 | HIGH |
| MAIL-011 | Tamaño de clave DKIM 1024–2047 bits (por debajo de los 2048 recomendados) | RFC 6376 | MEDIUM |
| MAIL-012 | STARTTLS no anunciado en puerto 25 (SMTP en texto claro permitido) | RFC 3207 | HIGH |
| MAIL-013 | Open relay: RCPT TO externo aceptado sin autenticación | RFC 5321 | CRITICAL |

### Aviso legal

Uso exclusivo en sistemas propios o para los que se dispone de autorización escrita explícita del titular del dominio. El sondeo SMTP activo (sin `--no-smtp`) realiza conexiones live a los servidores de correo objetivo. VampSecure Studios no asume responsabilidad por el uso no autorizado.

### Parte del toolkit VampSecure Labs

`vamp-mail-audit` es una herramienta del toolkit de investigación en seguridad de VampSecure Labs. Para el toolkit completo, incluyendo el orquestador que ejecuta todas las herramientas en secuencia y agrega los hallazgos en un único informe de engagement, ver:

- Portfolio: [github.com/Vampsecure-Labs](https://github.com/Vampsecure-Labs)

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v1.2 | README bilingüe (EN/ES) |
| v1.1 | Checks SPF/DKIM/DMARC/SMTP, escaneo en lote, informe de engagement para cliente |

---

© VampSecure Studios — VampSecure Labs Security Research Division
