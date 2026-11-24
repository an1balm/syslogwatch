"""Informes: markdown para leer/pegar, HTML autónomo para abrir y JSON para automatizar."""

from __future__ import annotations

import html as html_lib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Sequence

from .rank import Finding, summarize

BANDS = ((80, "CRÍTICO"), (60, "ALTO"), (40, "MEDIO"), (20, "BAJO"), (0, "RUIDO"))


def band(score: int) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "RUIDO"


def _md_escape(text: str) -> str:
    return (text or "").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;").replace("\n", " ")


def _md_link(text: str, url: str) -> str:
    return f"[{_md_escape(text)}]({url})"


@dataclass
class Report:
    findings: List[Finding] = field(default_factory=list)
    total_events: int = 0
    window: str = "todo el histórico"
    devices: Sequence[str] = ()
    generated_at: Optional[datetime] = None
    degraded: bool = False
    queries: Sequence[str] = ()
    stats: Optional[Dict] = None

    def __post_init__(self) -> None:
        self.generated_at = self.generated_at or datetime.now()
        self.devices = list(self.devices) or sorted({d for f in self.findings for d in f.devices})


def _header_lines(report: Report) -> List[str]:
    stamp = report.generated_at.strftime("%Y-%m-%d %H:%M")
    lines = [
        f"# Syslogwatch — {stamp}",
        "",
        f"**Ventana:** {report.window} · **Eventos analizados:** {report.total_events} · "
        f"**Dispositivos:** {len(report.devices)}",
    ]
    if report.devices:
        lines.append("**Emisores:** " + ", ".join(f"`{d}`" for d in report.devices))
    if report.degraded:
        lines.append(
            "> Aviso: no se pudo consultar alguna fuente externa (sin conexión o límite de peticiones). "
            "Las referencias del catálogo siguen siendo válidas."
        )
    lines.append("")
    return lines


def _category_table(report: Report) -> List[str]:
    lines = ["## Resumen por categoría", "", "| Categoría | Mensajes |", "| --- | ---: |"]
    for category, count in summarize(report.findings).items():
        lines.append(f"| {_md_escape(category)} | {count} |")
    return lines + [""]


def _ranking_table(report: Report) -> List[str]:
    lines = [
        "## Ranking de importancia",
        "",
        "| # | Importancia | Hallazgo | Categoría | Veces | Dispositivos |",
        "| ---: | --- | --- | --- | ---: | --- |",
    ]
    for position, finding in enumerate(report.findings, start=1):
        lines.append(
            f"| {position} | **{finding.score}** ({band(finding.score)}) | {_md_escape(finding.rule.title)} "
            f"| {_md_escape(finding.rule.category)} | {finding.count} | "
            f"{_md_escape(', '.join(finding.devices) or '—')} |"
        )
    return lines + [""]


def _finding_markdown(finding: Finding, position: int) -> List[str]:
    lines = [
        f"### {position}. {finding.rule.title}",
        "",
        f"- **Importancia:** {finding.score}/100 ({band(finding.score)}) · "
        f"**severidad máxima:** `{finding.severity_name}` · **repeticiones:** {finding.count}",
        f"- **Dispositivos:** {', '.join(f'`{d}`' for d in finding.devices) or '—'}",
    ]
    if finding.first_seen and finding.last_seen:
        lines.append(
            f"- **Periodo:** {finding.first_seen.strftime('%d-%b %H:%M:%S')} → "
            f"{finding.last_seen.strftime('%d-%b %H:%M:%S')}"
        )
    lines += ["", f"**Por qué falla.** {_md_escape(finding.rule.cause)}", ""]
    lines += [f"**Cómo se resuelve.** {_md_escape(finding.rule.fix)}", ""]
    if finding.samples:
        lines += ["**Mensajes de ejemplo:**", ""] + [f"> `{sample}`" for sample in finding.samples] + [""]
    if finding.references:
        links = " · ".join(
            _md_link(f"{ref.title} ({ref.source})", ref.url) for ref in finding.references
        )
        lines += [f"**Referencias externas.** {links}", ""]
    else:
        lines += ["**Referencias externas.** Sin referencias para este patrón.", ""]
    return lines


def render_markdown(report: Report) -> str:
    lines = _header_lines(report)
    if not report.findings:
        lines.append("Sin mensajes en la ventana analizada.")
        return "\n".join(lines) + "\n"

    lines += _category_table(report) + _ranking_table(report) + ["## Detalle", ""]
    for position, finding in enumerate(report.findings, start=1):
        lines += _finding_markdown(finding, position)
    return "\n".join(lines) + "\n"


_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin: 0; padding: 32px clamp(16px, 5vw, 64px); font-family: -apple-system, BlinkMacSystemFont,
       "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.5; }
h1 { font-size: 1.7rem; margin: 0 0 4px; }
h2 { font-size: 1.15rem; margin: 32px 0 8px; text-transform: uppercase; letter-spacing: .06em; opacity: .7; }
h3 { font-size: 1.05rem; margin: 0 0 8px; }
.meta { opacity: .75; font-size: .9rem; margin-bottom: 8px; }
.warn { border-left: 3px solid #d97706; padding: 8px 12px; margin: 16px 0; font-size: .92rem; }
table { border-collapse: collapse; width: 100%; font-size: .92rem; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid rgba(128,128,128,.28); }
th { font-weight: 600; font-size: .78rem; text-transform: uppercase; letter-spacing: .05em; opacity: .65; }
td.num { font-variant-numeric: tabular-nums; }
.finding { border: 1px solid rgba(128,128,128,.28); border-radius: 10px; padding: 16px 18px; margin: 14px 0; }
.finding .row { display: flex; flex-wrap: wrap; gap: 10px; align-items: baseline; }
.score { font-weight: 700; font-variant-numeric: tabular-nums; }
.tag { font-size: .72rem; text-transform: uppercase; letter-spacing: .06em; padding: 2px 8px;
       border-radius: 999px; border: 1px solid currentColor; }
.CRÍTICO { color: #dc2626; } .ALTO { color: #ea580c; } .MEDIO { color: #ca8a04; }
.BAJO { color: #2563eb; } .RUIDO { color: #6b7280; }
.label { font-size: .78rem; font-weight: 700; text-transform: uppercase; letter-spacing: .05em;
         opacity: .55; margin-top: 12px; }
code, blockquote { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .84rem; }
blockquote { margin: 4px 0; padding: 4px 10px; border-left: 2px solid rgba(128,128,128,.45); opacity: .9; }
a { color: inherit; text-decoration-color: rgba(128,128,128,.6); }
ul.refs { margin: 4px 0 0; padding-left: 18px; }
"""


def _e(text: str) -> str:
    return html_lib.escape(text or "", quote=True)


def _html_table(report: Report) -> List[str]:
    body = ["<h2>Ranking de importancia</h2>", "<table><thead><tr>",
            "<th>#</th><th>Importancia</th><th>Hallazgo</th><th>Categoría</th>",
            "<th>Veces</th><th>Dispositivos</th></tr></thead><tbody>"]
    for position, finding in enumerate(report.findings, start=1):
        body.append(
            f'<tr><td class="num">{position}</td>'
            f'<td class="num"><span class="score {band(finding.score)}">{finding.score}</span> '
            f'{band(finding.score)}</td>'
            f"<td>{_e(finding.rule.title)}</td><td>{_e(finding.rule.category)}</td>"
            f'<td class="num">{finding.count}</td>'
            f"<td>{_e(', '.join(finding.devices) or '—')}</td></tr>"
        )
    return body + ["</tbody></table>"]


def _html_finding(finding: Finding) -> str:
    refs = "".join(
        f'<li><a href="{_e(ref.url)}">{_e(ref.title)}</a> '
        f'<span class="meta">({_e(ref.source)})</span></li>'
        for ref in finding.references
        if ref.url.startswith(("http://", "https://"))
    )
    samples = "".join(f"<blockquote>{_e(s)}</blockquote>" for s in finding.samples)
    samples_html = '<div class="label">Mensajes de ejemplo</div>' + samples if samples else ""
    refs_html = (
        '<div class="label">Referencias externas</div><ul class="refs">' + refs + "</ul>"
        if refs
        else ""
    )
    return (
        '<div class="finding">'
        f'<div class="row"><h3>{_e(finding.rule.title)}</h3>'
        f'<span class="score {band(finding.score)}">{finding.score}/100</span>'
        f'<span class="tag {band(finding.score)}">{band(finding.score)}</span></div>'
        f'<div class="meta">{finding.count} repeticiones · severidad '
        f"<code>{_e(finding.severity_name)}</code> · "
        f"{_e(', '.join(finding.devices) or '—')}</div>"
        '<div class="label">Por qué falla</div>'
        f"<p>{_e(finding.rule.cause)}</p>"
        '<div class="label">Cómo se resuelve</div>'
        f"<p>{_e(finding.rule.fix)}</p>"
        f"{samples_html}"
        f"{refs_html}"
        "</div>"
    )


def render_html(report: Report) -> str:
    stamp = report.generated_at.strftime("%Y-%m-%d %H:%M")
    body = [
        "<!DOCTYPE html>",
        '<html lang="es"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>Syslogwatch — {_e(stamp)}</title>",
        f"<style>{_CSS}</style></head><body>",
        "<h1>Syslogwatch</h1>",
        f'<div class="meta">{_e(report.window)} · {report.total_events} eventos · '
        f"{len(report.devices)} dispositivos · {_e(stamp)}</div>",
    ]
    if report.degraded:
        body.append(
            '<div class="warn">No se pudo consultar alguna fuente externa; las referencias del '
            "catálogo siguen siendo válidas.</div>"
        )

    if not report.findings:
        body.append("<p>Sin mensajes en la ventana analizada.</p>")
    else:
        body += _html_table(report) + ["<h2>Detalle</h2>"]
        body += [_html_finding(finding) for finding in report.findings]

    body += ["</body></html>"]
    return "\n".join(body) + "\n"


def to_json(report: Report) -> str:
    payload = {
        "generated_at": report.generated_at.isoformat(timespec="seconds"),
        "window": report.window,
        "total_events": report.total_events,
        "devices": list(report.devices),
        "degraded": report.degraded,
        "findings": [
            {
                "rule_id": f.rule.id,
                "title": f.rule.title,
                "category": f.rule.category,
                "score": f.score,
                "band": band(f.score),
                "count": f.count,
                "severity": f.severity_name,
                "devices": f.devices,
                "samples": f.samples,
                "cause": f.rule.cause,
                "fix": f.rule.fix,
                "references": [
                    {"source": r.source, "title": r.title, "url": r.url} for r in f.references
                ],
            }
            for f in report.findings
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)
