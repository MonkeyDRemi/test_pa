from __future__ import annotations
import ast
import os
import sys
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

from core.models import Vulnerability
from core.scorer import compute_score
from core.reporter import generate_html, generate_markdown
from core.dedupe import dedupe_vulnerabilities
from core.suppressions import filter_suppressed
from core.secrets_scanner import scan_text_for_secrets
from core.sca_scanner import scan_dependencies
from parsers.py_parser import PythonScanner
from parsers.js_parser import JavaScriptScanner
from parsers.php_parser import PHPScanner


app     = typer.Typer(add_completion=False, help="APSA — Analyseur de sécurité statique (SAST)")
console = Console()

_SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH"    : "red",
    "MEDIUM"  : "yellow",
    "LOW"     : "green",
}

_BANNER = """[bold cyan]
   █████╗ ██████╗ ███████╗ █████╗ 
  ██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ███████║██████╔╝███████╗███████║
  ██╔══██║██╔═══╝ ╚════██║██╔══██║
  ██║  ██║██║     ███████║██║  ██║
  ╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
[/bold cyan][dim]  Static Application Security Testing — ESGI 2025-2026[/dim]
"""

def _load_config(config_path: str = "config.yaml") -> dict:
    try:
        with open(config_path, "r", encoding="utf-8-sig") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


def _scan_directory(target: str, config: dict) -> list[Vulnerability]:
    """Parcourt le dossier cible et lance les parsers adaptés."""
    all_vulns: list[Vulnerability] = []
    target_path = Path(target)

    py_files  = list(target_path.rglob("*.py"))
    js_files  = list(target_path.rglob("*.js"))
    php_files = list(target_path.rglob("*.php"))
    total     = len(py_files) + len(js_files) + len(php_files)

    if total == 0:
        return []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Analyse en cours…", total=total)

        for fp in py_files:
            progress.update(task, description=f"[cyan]Python[/cyan]  {fp.name}")
            try:
                with open(fp, "r", encoding="utf-8-sig", errors="ignore") as f:
                    content = f.read()
                tree = ast.parse(content)
                scanner = PythonScanner(str(fp), config)
                scanner.visit(tree)
                all_vulns.extend(scanner.findings)
                all_vulns.extend(scan_text_for_secrets(str(fp), content))
            except SyntaxError as e:
                console.print(f"[yellow]⚠  Syntaxe Python invalide dans {fp.name}: {e}[/yellow]")
            except Exception as e:
                console.print(f"[red]Erreur Python {fp.name}: {e}[/red]")
            progress.advance(task)

        for fp in js_files:
            progress.update(task, description=f"[yellow]JS     [/yellow]  {fp.name}")
            try:
                scanner = JavaScriptScanner(str(fp), config)
                findings = scanner.scan()
                if getattr(scanner, "_stderr_msg", None):
                    console.print(f"[yellow]⚠  {scanner._stderr_msg}[/yellow]")
                all_vulns.extend(findings)
                with open(fp, "r", encoding="utf-8-sig", errors="ignore") as f:
                    all_vulns.extend(scan_text_for_secrets(str(fp), f.read()))
            except Exception as e:
                console.print(f"[red]Erreur JS {fp.name}: {e}[/red]")
            progress.advance(task)

        for fp in php_files:
            progress.update(task, description=f"[magenta]PHP    [/magenta]  {fp.name}")
            try:
                scanner = PHPScanner(str(fp), config)
                findings = scanner.scan()
                if getattr(scanner, "_stderr_msg", None):
                    console.print(f"[yellow]⚠  {scanner._stderr_msg}[/yellow]")
                all_vulns.extend(findings)
                with open(fp, "r", encoding="utf-8-sig", errors="ignore") as f:
                    all_vulns.extend(scan_text_for_secrets(str(fp), f.read()))
            except Exception as e:
                console.print(f"[red]Erreur PHP {fp.name}: {e}[/red]")
            progress.advance(task)

    return all_vulns


def _display_results(vulns: list[Vulnerability]) -> None:
    """Affiche les vulnérabilités dans un tableau Rich."""
    if not vulns:
        console.print(Panel("[bold green]✅ Aucune vulnérabilité détectée ![/bold green]",
                            border_style="green"))
        return

    table = Table(
        title="Vulnérabilités détectées",
        box=box.ROUNDED,
        border_style="dim",
        header_style="bold white on #1a202c",
        show_lines=True,
    )
    table.add_column("Fichier",     style="cyan",    max_width=28, no_wrap=True)
    table.add_column("Ln",          style="magenta", width=5,  justify="right")
    table.add_column("Gravité",     width=10)
    table.add_column("Règle",       style="dim",     max_width=30)
    table.add_column("Description", max_width=55)

    for v in sorted(vulns, key=lambda x: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.severity, 9),
        x.file, x.line
    )):
        color = _SEVERITY_COLORS.get(v.severity, "white")
        table.add_row(
            Path(v.file).name,
            str(v.line),
            f"[{color}]{v.severity}[/{color}]",
            v.rule_id,
            v.description,
        )

    console.print(table)


def _display_score(score) -> None:
    """Affiche le score global sous forme de panel coloré."""
    grade_styles = {"A": "green", "B": "yellow", "C": "orange3", "D": "red", "F": "bold red"}
    style = grade_styles.get(score.grade, "white")

    breakdown = "  ".join(
        f"[{_SEVERITY_COLORS.get(s, 'white')}]{s}: {c}[/{_SEVERITY_COLORS.get(s,'white')}]"
        for s, c in score.by_severity.items()
    )

    content = (
        f"[{style}]Grade : {score.grade}   Score : {score.score}/100[/{style}]\n"
        f"{score.summary}\n\n"
        f"{breakdown}"
    )
    console.print(Panel(content, title="[bold]Bilan de sécurité[/bold]", border_style=style))


def _display_ai_advices(advices: dict) -> None:
    if not advices:
        return
    console.print("\n[bold cyan]🤖 Analyse IA (Gemini 2.5 Flash Lite)[/bold cyan]\n")
    for rule_id, advice in advices.items():
        if advice.error:
            console.print(f"[red]⚠  {rule_id} — Erreur API: {advice.error}[/red]")
            continue
        content = (
            f"[bold]Explication[/bold]\n{advice.explication}\n\n"
            f"[bold]Impact[/bold]\n{advice.impact}\n\n"
            f"[bold]Correction suggérée[/bold]\n[dim]{advice.fix}[/dim]"
        )
        console.print(Panel(content, title=f"[yellow]{rule_id}[/yellow]",
                            border_style="cyan", padding=(1, 2)))


@app.command()
def scan(
    target: str = typer.Argument(
        ..., help="Chemin du dossier ou fichier à analyser"
    ),
    report: Optional[str] = typer.Option(
        None, "--report", "-r",
        help="Format du rapport : 'html' ou 'md'",
        metavar="FORMAT",
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Chemin du fichier de sortie (défaut : report.html ou report.md)",
        metavar="FILE",
    ),
    ai: bool = typer.Option(
        False, "--ai",
        help="Activer l'analyse IA via Gemini 2.5 Flash Lite",
    ),
    gemini_key: Optional[str] = typer.Option(
        None, "--gemini-key",
        help="Clé API Google Gemini (ou variable d'env GEMINI_API_KEY)",
        envvar="GEMINI_API_KEY",
    ),
    max_ai: int = typer.Option(
        10, "--max-ai",
        help="Nombre max de vulnérabilités à envoyer à l'IA (défaut : 10)",
    ),
    sca: bool = typer.Option(
        True, "--sca/--no-sca",
        help="Scanner requirements.txt / package.json (CVE via OSV.dev)",
    ),
    ignore_markers: bool = typer.Option(
        True, "--ignore-markers/--no-ignore-markers",
        help="Respecter les commentaires `apsa-ignore` dans le code",
    ),
    config_file: str = typer.Option(
        "config.yaml", "--config", "-c",
        help="Chemin du fichier de configuration",
    ),
    no_banner: bool = typer.Option(
        False, "--no-banner", hidden=True,
    ),
):

    if not no_banner:
        console.print(_BANNER)

    if not os.path.exists(target):
        console.print(f"[bold red]Erreur :[/bold red] Chemin introuvable : {target}")
        raise typer.Exit(code=1)

    config = _load_config(config_file)

    target_path = Path(target)
    has_source_files = any(next(target_path.rglob(ext), None) is not None
                            for ext in ("*.py", "*.js", "*.php"))
    has_manifests     = any(next(target_path.rglob(m), None) is not None
                            for m in ("requirements.txt", "package.json"))

    if not has_source_files and not has_manifests:
        console.print("[yellow]Aucun fichier .py / .js / .php ni manifeste "
                       "(requirements.txt / package.json) trouvé dans la cible.[/yellow]")
        raise typer.Exit(code=0)

    if not has_source_files:
        console.print("[dim]Aucun fichier .py / .js / .php — seul le scan de "
                       "dépendances (SCA) sera effectué.[/dim]")

    console.rule("[bold]Scan en cours[/bold]")
    vulns = _scan_directory(target, config)

    if sca:
        with console.status("[cyan]Vérification des dépendances (OSV.dev)…[/cyan]"):
            sca_vulns = scan_dependencies(Path(target))
        if sca_vulns:
            console.print(f"[dim]📦 {len(sca_vulns)} vulnérabilité(s) de dépendance(s) trouvée(s)[/dim]")
        vulns.extend(sca_vulns)

    vulns, dup_count = dedupe_vulnerabilities(vulns)
    if dup_count:
        console.print(f"[dim]🧹 {dup_count} doublon(s) supprimé(s)[/dim]")

    if ignore_markers:
        vulns, ignored_count = filter_suppressed(vulns)
        if ignored_count:
            console.print(f"[dim]🙈 {ignored_count} finding(s) ignoré(s) via `apsa-ignore`[/dim]")

    console.print(f"[dim]{len(vulns)} vulnérabilité(s) trouvée(s) dans[/dim] [cyan]{target}[/cyan]\n")

    _display_results(vulns)

    score = compute_score(vulns)
    _display_score(score)

    if ai:
        if gemini_key:
            os.environ["GOOGLE_API_KEY"] = gemini_key
        if vulns:
            from core.ai_advisor import enrich_vulnerabilities
            console.rule("[bold cyan]Analyse IA[/bold cyan]")
            with console.status("[cyan]Interrogation de Gemini…[/cyan]"):
                advices = enrich_vulnerabilities(vulns, max_calls=max_ai)
            _display_ai_advices(advices)
        else:
            console.print("[green]Aucune vulnérabilité à analyser par l'IA.[/green]")

    if report:
        fmt = report.lower().strip()
        if fmt not in ("html", "md", "markdown"):
            console.print(f"[red]Format inconnu '{report}'. Utilise 'html' ou 'md'.[/red]")
            raise typer.Exit(code=1)

        ai_advices = {}
        if ai:
            try:
                ai_advices = advices
            except NameError:
                pass

        if fmt == "html":
            dest = output or "report.html"
            path = generate_html(vulns, score, target, dest, ai_advices=ai_advices)
            console.print(f"\n[bold green]✅ Rapport HTML généré :[/bold green] {path}")
        else:
            dest = output or "report.md"
            path = generate_markdown(vulns, score, target, dest, ai_advices=ai_advices)
            console.print(f"\n[bold green]✅ Rapport Markdown généré :[/bold green] {path}")

    critical_count = score.by_severity.get("CRITICAL", 0) + score.by_severity.get("HIGH", 0)
    raise typer.Exit(code=1 if critical_count > 0 else 0)


@app.command()
def info():
    console.print(_BANNER)
    console.print(Panel(
        "[bold]Langages supportés[/bold]\n"
        "  [cyan]Python[/cyan]  (.py)  — AST natif Python\n"
        "  [yellow]JavaScript[/yellow] (.js)  — Analyse via Node.js\n"
        "  [magenta]PHP[/magenta]     (.php) — Analyse via PHP CLI\n\n"
        "[bold]Commandes[/bold]\n"
        "  [green]python main.py scan <dossier>[/green]                       Scan basique\n"
        "  [green]python main.py scan <dossier> --report html[/green]         + rapport HTML\n"
        "  [green]python main.py scan <dossier> --report md[/green]           + rapport Markdown\n"
        "  [green]python main.py scan <dossier> --ai --gemini-key KEY[/green] + analyse Gemini\n\n"
        "[bold]Auteurs[/bold]\n"
        "  Ahmed BENSAID & Remi VAVICHANDRAN — ESGI 2025-2026",
        title="APSA — Static Analyzer",
        border_style="cyan",
    ))


if __name__ == "__main__":
    app()
