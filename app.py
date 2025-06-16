from flask import Flask, render_template, request, redirect, url_for
import threading
import os
import json
from utils import report_generator
from main import run_all_scans

app = Flask(__name__)

RESULTS_DIR = "flask_reports"
os.makedirs(RESULTS_DIR, exist_ok=True)

def get_result_path(target):
    safe_target = target.replace("http://", "").replace("https://", "").replace("/", "_")
    return os.path.join(RESULTS_DIR, f"{safe_target}.json")

def run_scan_and_store(target):
    results = run_all_scans(target)
    report_generator.save_json_report(results, target, output_dir=RESULTS_DIR)
    report_generator.save_pdf_report(results, target, output_dir=RESULTS_DIR)
    report_generator.render_html_report(results, target, output_dir=RESULTS_DIR)

def load_results_from_disk(target):
    path = get_result_path(target)
    with open(path, "r") as f:
        return json.load(f)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/loading")
def loading():
    target = request.args.get("target")
    threading.Thread(target=run_scan_and_store, args=(target,)).start()
    return render_template("loading.html", target=target)

@app.route("/results")
def results():
    target = request.args.get("target")
    results = load_results_from_disk(target)
    return render_template("results.html", results=results, target=target)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
