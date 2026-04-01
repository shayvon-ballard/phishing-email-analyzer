import csv
import os
from datetime import datetime

def export_to_csv(analysis):
    os.makedirs("reports/output", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/output/phishing_analysis_{timestamp}.csv"

    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Type", "Finding"])
        
        for flag in analysis["header_flags"]:
            writer.writerow(["Header Flag", flag])
        
        for flag in analysis["url_flags"]:
            writer.writerow(["URL Flag", flag])
        
        for url in analysis["urls"]:
            writer.writerow(["URL Found", url])
        
        writer.writerow(["Risk Score", analysis["score"]])
        writer.writerow(["Risk Level", analysis["risk_level"]])

    return filename