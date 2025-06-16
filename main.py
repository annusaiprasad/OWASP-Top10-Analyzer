from scanner import (
    injection, access_control, crypto_failures, config_misconfig,
    insecure_design, outdated_components, auth_failures,
    integrity_failures, logging_monitoring, ssrf
)

from utils import report_generator, cvss_calculator
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

console = Console()


def run_all_scans(target_url):
    console.print(f"\n[bold cyan][+] Scanning Target:[/bold cyan] {target_url}\n")

    results = []

    modules = [
        injection, access_control, crypto_failures, config_misconfig,
        insecure_design, outdated_components, auth_failures,
        integrity_failures, logging_monitoring, ssrf
    ]

    module_names = {
        "injection": "Injection",
        "access_control": "Access Control",
        "crypto_failures": "Cryptographic Failures",
        "config_misconfig": "Security Misconfiguration",
        "insecure_design": "Insecure Design",
        "outdated_components": "Outdated Components",
        "auth_failures": "Auth Failures",
        "integrity_failures": "Integrity Failures",
        "logging_monitoring": "Logging & Monitoring",
        "ssrf": "SSRF"
    }

    total_scans = len(modules)

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        transient=False,
    ) as progress:
        task = progress.add_task("Running Scans...", total=total_scans)

        for i, module in enumerate(modules):
            module_key = module.__name__.split('.')[-1]
            readable_name = module_names.get(module_key, module_key.replace('_', ' ').title())

            console.print(f"[yellow]→ Scanning {readable_name} ({i + 1}/{total_scans})[/yellow]")

            result = module.scan(target_url)

            # Assign CVSS score and risk level
            cvss_data = cvss_calculator.assign_cvss_score(result['vulnerability'], result['details'])
            result['cvss_score'] = cvss_data['score']
            result['risk_level'] = cvss_data['risk']
            results.append(result)

            console.print(f"[green]✔ {readable_name} completed[/green] • [bold magenta]{i + 1} done[/bold magenta], [cyan]{total_scans - i - 1} remaining[/cyan]\n")
            progress.advance(task)

    return results


if __name__ == "__main__":
    target = input("Enter the target URL (e.g., http://testphp.vulnweb.com): ").strip()
    results = run_all_scans(target)

    # Save reports
    report_generator.save_json_report(results, target)
    report_generator.save_pdf_report(results, target)
    report_generator.render_html_report(results, target)
