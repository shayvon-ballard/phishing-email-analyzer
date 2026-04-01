from flask import Flask, render_template, request
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.scorer import analyze_email
from reports.exporter import export_to_csv

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None

    if request.method == "POST":
        raw_email = request.form.get("raw_email", "").strip()
        if raw_email:
            try:
                result = analyze_email(raw_email)
            except Exception as e:
                error = f"Analysis failed: {str(e)}"

    return render_template("index.html", result=result, error=error)

@app.route("/export", methods=["POST"])
def export():
    from flask import redirect, url_for
    raw_email = request.form.get("raw_email", "").strip()
    if raw_email:
        result = analyze_email(raw_email)
        export_to_csv(result)
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)