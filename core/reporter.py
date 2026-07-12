from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from core.models import Vulnerability
from core.scorer import ScanScore

_SEVERITY_BADGE = {
    "CRITICAL": "badge-critical",
    "HIGH"    : "badge-high",
    "MEDIUM"  : "badge-medium",
    "LOW"     : "badge-low",
}
_GRADE_COLOR = {"A": "#38a169", "B": "#d69e2e", "C": "#dd6b20", "D": "#e53e3e", "F": "#742a2a"}



def generate_html(
    vulnerabilities: list[Vulnerability],
    score: ScanScore,
    target_path: str,
    output_path: str = "report.html",
    ai_advices: dict | None = None,
) -> str:
    now         = datetime.now().strftime("%d/%m/%Y %H:%M")
    grade_color = _GRADE_COLOR.get(score.grade, "#718096")
    ai_advices  = ai_advices or {}

    rows = ""
    for v in vulnerabilities:
        badge      = _SEVERITY_BADGE.get(v.severity, "badge-low")
        has_advice = v.rule_id in ai_advices and not ai_advices[v.rule_id].error
        ai_btn     = (
            f'<button class="ai-btn" onclick="toggleAI(\'{v.rule_id}\')">'
            f'🤖 Voir analyse IA</button>'
        ) if has_advice else ""
        rows += f"""
        <tr>
          <td class="td-file">{Path(v.file).name}</td>
          <td class="td-line">{v.line}</td>
          <td><span class="badge {badge}">{v.severity}</span></td>
          <td class="td-rule">{v.rule_id}</td>
          <td>{v.description} {ai_btn}</td>
        </tr>"""

    ai_panels = ""
    for rule_id, advice in ai_advices.items():
        if advice.error:
            continue
        fix_escaped = (advice.fix
                       .replace("&", "&amp;")
                       .replace("<", "&lt;")
                       .replace(">", "&gt;"))
        ai_panels += f"""
        <div class="ai-panel" id="ai-{rule_id}" style="display:none">
          <div class="ai-section"><span class="ai-label">📋 Explication</span>
            <p>{advice.explication}</p></div>
          <div class="ai-section"><span class="ai-label">💥 Impact</span>
            <p>{advice.impact}</p></div>
          <div class="ai-section"><span class="ai-label">🔧 Correction suggérée</span>
            <pre><code>{fix_escaped}</code></pre></div>
        </div>"""

    ai_section_html = ""
    if ai_advices and any(not a.error for a in ai_advices.values()):
        ai_section_html = f"""
        <h2 class="section-title">🤖 Analyse IA — Gemini 2.5 Flash</h2>
        {ai_panels}"""

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>APSA — Rapport de Sécurité</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f1117; color: #e2e8f0; }}
    header {{ background: linear-gradient(135deg, #1a1f2e 0%, #16213e 100%);
              padding: 2rem 3rem; border-bottom: 1px solid #2d3748; }}
    header h1 {{ font-size: 1.8rem; letter-spacing: 2px; color: #63b3ed; }}
    header p  {{ color: #718096; margin-top: 0.3rem; font-size: 0.9rem; }}
    .container {{ max-width: 1200px; margin: 2rem auto; padding: 0 2rem; }}

    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
              gap: 1rem; margin-bottom: 2rem; }}
    .card {{ background: #1a202c; border: 1px solid #2d3748; border-radius: 10px;
             padding: 1.2rem; text-align: center; }}
    .card .val {{ font-size: 2.2rem; font-weight: 700; }}
    .card .lbl {{ font-size: 0.78rem; color: #718096; text-transform: uppercase;
                  letter-spacing: 1px; margin-top: 0.3rem; }}

    .summary-box {{ background: #1a202c; border-left: 4px solid {grade_color};
                    border-radius: 6px; padding: 1rem 1.5rem; margin-bottom: 2rem; color: #cbd5e0; }}

    .table-wrap {{ overflow-x: auto; background: #1a202c; border-radius: 10px;
                   border: 1px solid #2d3748; margin-bottom: 2rem; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
    thead th {{ background: #2d3748; padding: 0.85rem 1rem; text-align: left;
                font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; color: #a0aec0; }}
    tbody tr:hover {{ background: #2d3748; }}
    td {{ padding: 0.75rem 1rem; border-top: 1px solid #2d3748; vertical-align: top; }}
    .td-file {{ color: #63b3ed; font-family: monospace; white-space: nowrap; }}
    .td-line {{ color: #a0aec0; text-align: center; }}
    .td-rule {{ color: #e2e8f0; font-family: monospace; font-size: 0.78rem; }}

    .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px;
              font-size: 0.72rem; font-weight: 700; letter-spacing: 0.5px; }}
    .badge-critical {{ background: #742a2a; color: #feb2b2; }}
    .badge-high     {{ background: #7b341e; color: #fbd38d; }}
    .badge-medium   {{ background: #744210; color: #fefcbf; }}
    .badge-low      {{ background: #1c4532; color: #9ae6b4; }}

    /* Bouton IA */
    .ai-btn {{ background: #2b4a7a; color: #90cdf4; border: 1px solid #4a90d9;
               border-radius: 4px; padding: 0.2rem 0.6rem; font-size: 0.72rem;
               cursor: pointer; margin-left: 0.5rem; white-space: nowrap; }}
    .ai-btn:hover {{ background: #3b5e9a; }}

    /* Panneaux IA */
    .section-title {{ font-size: 1.2rem; color: #63b3ed; margin: 2rem 0 0.5rem; }}
    .section-sub   {{ color: #718096; font-size: 0.85rem; margin-bottom: 1.5rem; }}
    .ai-panel {{ background: #1a202c; border: 1px solid #2b4a7a; border-radius: 10px;
                 padding: 1.5rem; margin-bottom: 1rem; }}
    .ai-label {{ display: inline-block; font-weight: 700; color: #63b3ed;
                 margin-bottom: 0.5rem; font-size: 0.9rem; }}
    .ai-section {{ margin-bottom: 1rem; }}
    .ai-section p {{ color: #cbd5e0; line-height: 1.6; }}
    .ai-panel pre {{ background: #0f1117; border: 1px solid #2d3748; border-radius: 6px;
                     padding: 1rem; overflow-x: auto; margin-top: 0.5rem; }}
    .ai-panel code {{ font-family: 'Consolas', 'Courier New', monospace;
                      font-size: 0.82rem; color: #9ae6b4; }}

    footer {{ text-align: center; color: #4a5568; padding: 2rem; font-size: 0.8rem; }}
  </style>
</head>
<body>
  <header>
    <h1>🛡 APSA — Static Analyzer</h1>
    <p>Rapport généré le {now} &nbsp;|&nbsp; Cible : <code>{target_path}</code></p>
  </header>

  <div class="container">
    <div class="cards">
      <div class="card">
        <div class="val" style="color:#63b3ed">{score.total_issues}</div>
        <div class="lbl">Vulnérabilités</div>
      </div>
      <div class="card">
        <div class="val" style="color:{grade_color}">{score.grade}</div>
        <div class="lbl">Grade sécurité</div>
      </div>
      <div class="card">
        <div class="val" style="color:{grade_color}">{score.score}/100</div>
        <div class="lbl">Score de risque</div>
      </div>
      <div class="card">
        <div class="val" style="color:#e53e3e">{score.by_severity.get('CRITICAL', 0)}</div>
        <div class="lbl">Critiques</div>
      </div>
      <div class="card">
        <div class="val" style="color:#dd6b20">{score.by_severity.get('HIGH', 0)}</div>
        <div class="lbl">Élevées</div>
      </div>
    </div>

    <div class="summary-box">{score.summary}</div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Fichier</th><th>Ligne</th><th>Gravité</th><th>Règle</th><th>Description</th></tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </div>

    {ai_section_html}
  </div>

  <footer>APSA SAST &mdash; Ahmed BENSAID &amp; Remi VAVICHANDRAN &mdash; ESGI 2025-2026</footer>

  <script>
    function toggleAI(ruleId) {{
      const panel = document.getElementById('ai-' + ruleId);
      if (!panel) return;
      const isVisible = panel.style.display !== 'none';
      // Ferme tous les panneaux
      document.querySelectorAll('.ai-panel').forEach(p => p.style.display = 'none');
      document.querySelectorAll('.ai-btn').forEach(b => b.textContent = '🤖 Voir analyse IA');
      // Ouvre le panel cliqué si c'était fermé
      if (!isVisible) {{
        panel.style.display = 'block';
        panel.scrollIntoView({{ behavior: 'smooth', block: 'nearest' }});
        event.target.textContent = '🔼 Masquer';
      }}
    }}
  </script>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    return output_path


def generate_markdown(
    vulnerabilities: list[Vulnerability],
    score: ScanScore,
    target_path: str,
    output_path: str = "report.md",
    ai_advices: dict | None = None,
) -> str:
    now        = datetime.now().strftime("%d/%m/%Y %H:%M")
    ai_advices = ai_advices or {}

    lines = [
        "# 🛡 APSA — Rapport de Sécurité",
        f"\n**Généré le** {now}  |  **Cible** : `{target_path}`",
        f"\n## Score Global\n",
        "| Métrique | Valeur |", "|---|---|",
        f"| Grade | **{score.grade}** |",
        f"| Score de risque | {score.score}/100 |",
        f"| Total vulnérabilités | {score.total_issues} |",
    ]
    for sev, count in score.by_severity.items():
        lines.append(f"| {sev} | {count} |")

    lines += [
        f"\n> {score.summary}",
        "\n## Détail des Vulnérabilités\n",
        "| Fichier | Ligne | Gravité | Règle | Description |",
        "|---|---|---|---|---|",
    ]
    for v in vulnerabilities:
        lines.append(
            f"| `{Path(v.file).name}` | {v.line} | **{v.severity}** "
            f"| `{v.rule_id}` | {v.description} |"
        )

    valid_advices = {k: v for k, v in ai_advices.items() if not v.error}
    if valid_advices:
        lines.append("\n## 🤖 Analyse IA — Gemini 2.5 Flash\n")
        for rule_id, advice in valid_advices.items():
            lines += [
                f"### `{rule_id}`",
                f"\n**Explication**\n{advice.explication}",
                f"\n**Impact**\n{advice.impact}",
                f"\n**Correction suggérée**\n```\n{advice.fix}\n```\n",
            ]

    lines.append("\n---\n*APSA SAST — Ahmed BENSAID & Remi VAVICHANDRAN — ESGI 2025-2026*")
    Path(output_path).write_text("\n".join(lines), encoding="utf-8")
    return output_path
