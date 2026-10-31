"""Output formatters for d1-triage CLI (Rich terminal UI and JSON)."""
import json
from typing import List

from d1_triage.engine import TriageResult


def print_terminal_results(results: List[TriageResult], model_name: str = "LiquidAI/d1-3B", device: str = "cpu", show_explanations: bool = True):
    """Print results using Rich terminal formatting."""
    try:
        from rich import box
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        # Use comfortable width for table readability
        console = Console(width=100)
    except ImportError:
        console = None

    if console is None:
        # Plain text fallback
        print("\n" + "=" * 80)
        print(f" Liquid AI d1-3B Triage Results | Device: {device.upper()}")
        print("=" * 80)
        for r in results:
            tag = "[ALERT]" if r.is_exploitable else "[SAFE] "
            print(f"{tag} {r.decision:<14} | P(TP): {r.p_tp:.3f} ({r.confidence_pct:.1f}%) | {r.rule} | Line {r.line_number}")
            print(f"       Sink: {r.sink_statement}")
            if r.explanation:
                print(f"       Rationale: {r.explanation}")
        return

    # Rich formatted output with responsive columns
    table = Table(
        title=f"Static Analysis Triage Report ({model_name} on {device.upper()})",
        show_header=True,
        header_style="bold magenta",
        box=box.ROUNDED,
        expand=True,
    )
    table.add_column("Status", justify="center", no_wrap=True)
    table.add_column("Rule / CWE", style="cyan", overflow="fold")
    table.add_column("Location", style="yellow", no_wrap=True)
    table.add_column("Flagged Sink Statement", overflow="fold")
    table.add_column("P(TP)", justify="right", no_wrap=True)
    table.add_column("Confidence", justify="right", no_wrap=True)
    table.add_column("Latency", justify="right", no_wrap=True)

    total_tp = 0
    total_fp = 0
    total_time = 0.0

    for r in results:
        total_time += r.latency_ms
        if r.is_exploitable:
            total_tp += 1
            status_style = "[bold red]EXPLOITABLE[/bold red]"
        else:
            total_fp += 1
            status_style = "[bold green]GUARDED / FP[/bold green]"

        loc_str = f"{r.file_path.split('/')[-1]}:{r.line_number}"
        rule_short = r.rule.split('.')[-1]
        rule_cell = f"{rule_short}\n[dim]({r.cwe})[/dim]"

        table.add_row(
            status_style,
            rule_cell,
            loc_str,
            r.sink_statement,
            f"{r.p_tp:.3f}",
            f"{r.confidence_pct:.1f}%",
            f"{r.latency_ms:.0f}ms",
        )

    console.print()
    console.print(table)

    # Print explanations panel if requested
    if show_explanations and any(r.explanation for r in results):
        exp_lines = []
        for r in results:
            badge = "[red]EXPLOITABLE[/red]" if r.is_exploitable else "[green]SAFE / FP[/green]"
            exp_lines.append(f"[bold]{r.finding_id}[/bold] ({badge} - {r.rule.split('.')[-1]}):")
            exp_lines.append(f"  [italic]{r.explanation}[/italic]\n")
        console.print(Panel("\n".join(exp_lines).strip(), title="Triage Remediation & Analysis Rationale", border_style="cyan", expand=False))

    noise_reduction = (total_fp / len(results) * 100.0) if results else 0.0
    avg_latency = (total_time / len(results)) if results else 0.0

    summary_text = (
        f"[bold]Total Alerts Analyzed:[/bold] {len(results)}\n"
        f"[bold red]True Positives (Exploitable):[/bold red] {total_tp} (require remediation)\n"
        f"[bold green]False Positives (Filtered):[/bold green] {total_fp} (suppressed safe patterns)\n"
        f"[bold cyan]Noise Reduction:[/bold cyan] {noise_reduction:.1f}% developer time saved\n"
        f"[bold yellow]Average Latency:[/bold yellow] {avg_latency:.1f} ms per alert"
    )
    console.print(Panel(summary_text, title="Triage Summary", expand=False))


def save_json_report(results: List[TriageResult], out_path: str):
    """Save structured triage results to a JSON file."""
    data = [
        {
            "id": r.finding_id,
            "rule": r.rule,
            "cwe": r.cwe,
            "file": r.file_path,
            "line": r.line_number,
            "decision": r.decision,
            "is_exploitable": r.is_exploitable,
            "p_tp": r.p_tp,
            "confidence_pct": r.confidence_pct,
            "sink_statement": r.sink_statement,
            "latency_ms": r.latency_ms,
            "device": r.device,
            "explanation": r.explanation,
            "ground_truth": r.ground_truth,
        }
        for r in results
    ]
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    print(f"Exported triage report to {out_path}")
