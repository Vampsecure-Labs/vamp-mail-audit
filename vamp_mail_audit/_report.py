# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_report.py — Generación de informes de la auditoría de correo.
Formatos: consola Rich, JSON, HTML dark-theme y formato unificado VSL.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ._models import (
    MailAuditResult,
    SEVERITY_COLOR,
    TOOL_NAME,
    VERSION,
)


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
                self._c.print("\n  [bold cyan]Remediaciones prioritarias:[/]")
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
            SEV_CSS.get(sev, "sev-info")
            badge_col  = SEV_BADGE_COLOR.get(sev, "#555")
            badge_text = "#fff" if sev in ("CRITICAL", "HIGH", "INFO", "LOW") else "#000"
            ts         = r.timestamp[:19].replace("T", " ") + " UTC" if r.timestamp else ""

            # Registros DNS
            def _rec(value: Optional[str], label: str) -> str:
                if not value:
                    return '<span class="sev-high">AUSENTE</span>'
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
