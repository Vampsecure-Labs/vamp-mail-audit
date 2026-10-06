# © VampSecure Studios — VampSecure Labs Security Research Division
"""
cli.py — Interfaz de línea de comandos de vamp-mail-audit.
Punto de entrada: main()
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

from rich.console import Console

from ._core import MailAuditor
from ._models import DKIM_SELECTORS, MailAuditResult, SEVERITY_ORDER, TOOL_NAME, VERSION
from ._report import Reporter, _findings_vsl

console = Console()

BANNER = r"""
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-mail-audit v1.2.0 · Email Security Auditor
  ────────────────────────────────────────────────────────────────────────
  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""


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
