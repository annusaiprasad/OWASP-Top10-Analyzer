import os
import json
from datetime import datetime
from fpdf import FPDF
from jinja2 import Environment, FileSystemLoader

def save_json_report(results, target_url, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)
    safe_target = target_url.replace("http://", "").replace("https://", "").replace("/", "_")
    path = os.path.join(output_dir, f"{safe_target}.json")

    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)

    print(f"[+] JSON report saved to {path}")

def save_pdf_report(results, target_url, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)
    safe_target = target_url.replace("http://", "").replace("https://", "").replace("/", "_")
    path = os.path.join(output_dir, f"{safe_target}.pdf")

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt=f"OWASP Scan Report for {target_url}", ln=True, align="C")

    for res in results:
        pdf.ln(10)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(200, 10, txt=f"{res['vulnerability']}:", ln=True)
        pdf.set_font("Arial", "", 11)
        pdf.cell(200, 10, txt=f"Status: {'VULNERABLE' if res['found'] else 'Secure'}", ln=True)
        pdf.multi_cell(0, 10, txt=f"Details: {res['details']}")
        pdf.cell(200, 10, txt=f"CVSS: {res.get('cvss_score', 'N/A')} ({res.get('risk_level', 'N/A')})", ln=True)
        if 'fix' in res:
            pdf.multi_cell(0, 10, txt=f"Fix: {res['fix']}")

    pdf.output(path)
    print(f"[+] PDF report saved to {path}")

def render_html_report(results, target_url, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("report_template.html")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html_content = template.render(results=results, target=target_url, timestamp=timestamp)

    safe_target = target_url.replace("http://", "").replace("https://", "").replace("/", "_")
    output_path = os.path.join(output_dir, f"{safe_target}.html")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[+] HTML report saved to {output_path}")
