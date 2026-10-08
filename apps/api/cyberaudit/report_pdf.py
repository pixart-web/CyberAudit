"""Deterministic, evidence-grounded PDF rendering for stored reports.

The PDF contains only what is recorded in the database: no invented
statistics, no placeholder charts. Imported/unverified findings and
AI-generated sections are explicitly labelled as such.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import BytesIO
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

SEVERITIES = ("critical", "high", "medium", "low")
_SEVERITY_COLORS = {
    "critical": colors.HexColor("#b42318"),
    "high": colors.HexColor("#d9480f"),
    "medium": colors.HexColor("#b7791f"),
    "low": colors.HexColor("#2b6cb0"),
}
BRAND = colors.HexColor("#0f766e")


@dataclass
class ReportFinding:
    title: str
    severity: str
    status: str
    verification: str
    component: str
    description: str
    remediation: str
    imported: bool = False


@dataclass
class ReportData:
    title: str
    report_type: str
    status: str
    organization: str
    client: str | None
    engagement_name: str
    engagement_code: str
    engagement_mode: str
    period: str
    generated_by: str
    generated_at: datetime
    scope_targets: list[str] = field(default_factory=list)
    findings: list[ReportFinding] = field(default_factory=list)
    evidence: list[tuple[str, str]] = field(default_factory=list)
    conclusions: list[tuple[str, str]] = field(default_factory=list)
    ai_sections: list[tuple[str, str]] = field(default_factory=list)


def _p(text: str) -> str:
    return escape(text or "—").replace("\n", "<br/>")


def render_report_pdf(data: ReportData, *, compress: bool = True) -> bytes:
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], textColor=BRAND, spaceAfter=6)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], textColor=BRAND, spaceBefore=12)
    body = ParagraphStyle("B", parent=styles["BodyText"], leading=14)
    small = ParagraphStyle("S", parent=body, fontSize=8, textColor=colors.HexColor("#555555"))
    buffer = BytesIO()

    def footer(canvas, doc):  # noqa: ANN001
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#666666"))
        canvas.drawString(20 * mm, 10 * mm, f"CyberAudit — {data.engagement_code} — Confidencial")
        canvas.drawRightString(A4[0] - 20 * mm, 10 * mm, f"Página {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=18 * mm,
        title=data.title,
        author="CyberAudit",
        pageCompression=1 if compress else 0,
    )
    story: list = [
        Spacer(1, 30 * mm),
        Paragraph("CYBERAUDIT", ParagraphStyle("Brand", parent=h1, fontSize=14)),
        Paragraph(_p(data.title), ParagraphStyle("T", parent=h1, fontSize=24, leading=28)),
        Spacer(1, 8 * mm),
    ]
    cover = [
        ["Organização", data.organization],
        ["Cliente", data.client or "—"],
        ["Auditoria", f"{data.engagement_name} ({data.engagement_code})"],
        ["Modo", data.engagement_mode],
        ["Período", data.period],
        ["Estado do relatório", data.status],
        ["Gerado por", data.generated_by],
        ["Data", data.generated_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")],
    ]
    table = Table(
        [[Paragraph(f"<b>{_p(k)}</b>", body), Paragraph(_p(v), body)] for k, v in cover],
        colWidths=[45 * mm, 120 * mm],
    )
    table.setStyle(
        TableStyle(
            [
                ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story += [table, PageBreak()]

    counts = {sev: sum(1 for f in data.findings if f.severity == sev) for sev in SEVERITIES}
    unverified = sum(1 for f in data.findings if f.verification != "confirmed")
    story.append(Paragraph("1. Sumário executivo", h1))
    if data.findings:
        story.append(
            Paragraph(
                f"Foram registados <b>{len(data.findings)}</b> findings nesta auditoria: "
                + ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s])
                + f". Destes, <b>{unverified}</b> não estão confirmados (importados ou por verificar).",
                body,
            )
        )
        sev_table = Table(
            [["Severidade", "Findings"], *[[s.capitalize(), str(counts[s])] for s in SEVERITIES]],
            colWidths=[50 * mm, 30 * mm],
        )
        sev_style: list[Any] = [
            ("BACKGROUND", (0, 0), (-1, 0), BRAND),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ]
        sev_style += [
            ("TEXTCOLOR", (0, i + 1), (0, i + 1), _SEVERITY_COLORS[s])
            for i, s in enumerate(SEVERITIES)
        ]
        sev_table.setStyle(TableStyle(sev_style))
        story += [Spacer(1, 4 * mm), sev_table]
    else:
        story.append(
            Paragraph(
                "Não existem findings registados para esta auditoria à data de geração.", body
            )
        )
    for heading, text in data.conclusions:
        story += [Paragraph(_p(heading), h2), Paragraph(_p(text), body)]

    story.append(Paragraph("2. Âmbito e metodologia", h1))
    story.append(Paragraph("Âmbito autorizado:", body))
    for target in data.scope_targets or ["(sem alvos autorizados registados)"]:
        story.append(Paragraph(f"• {_p(target)}", body))
    story.append(
        Paragraph(
            "Metodologia: análise de dados registados na plataforma CyberAudit (avaliações seguras e restritas ao âmbito, "
            "e resultados importados de ferramentas externas). Nenhuma exploração ativa foi realizada.",
            body,
        )
    )

    story.append(Paragraph("3. Findings", h1))
    for index, f in enumerate(
        sorted(
            data.findings,
            key=lambda x: SEVERITIES.index(x.severity) if x.severity in SEVERITIES else 9,
        ),
        1,
    ):
        color = _SEVERITY_COLORS.get(f.severity, colors.black)
        origin = " · importado de ferramenta externa" if f.imported else ""
        story.append(
            Paragraph(
                f'<font color="{color.hexval()}"><b>{index}. [{_p(f.severity.upper())}]</b></font> <b>{_p(f.title)}</b>',
                h2,
            )
        )
        story.append(
            Paragraph(
                f"Componente: {_p(f.component)} · Estado: {_p(f.status)} · Verificação: {_p(f.verification)}{origin}",
                small,
            )
        )
        story.append(Paragraph(_p(f.description), body))
        if f.remediation:
            story.append(Paragraph(f"<b>Remediação recomendada:</b> {_p(f.remediation)}", body))

    story.append(Paragraph("4. Evidência", h1))
    if data.evidence:
        for title, detail in data.evidence:
            story.append(Paragraph(f"• <b>{_p(title)}</b> — {_p(detail)}", body))
    else:
        story.append(Paragraph("Não existe evidência anexada a esta auditoria.", body))

    if data.ai_sections:
        story.append(Paragraph("5. Análise assistida por IA (requer revisão humana)", h1))
        for heading, text in data.ai_sections:
            story += [Paragraph(_p(heading), h2), Paragraph(_p(text), body)]

    story.append(Paragraph("Limitações", h1))
    story.append(
        Paragraph(
            "Este relatório reflete exclusivamente os dados registados na plataforma até à data de geração. "
            "Findings importados ou não confirmados não constituem prova de exploração. "
            "A ausência de findings não implica ausência de vulnerabilidades.",
            body,
        )
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
