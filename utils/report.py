from fileinput import filename
import os
import json

REPORTS_DIR = "reports"

def generate_report(url, findings, summary, timestamp):
    """
    Genera un reporte en archivo de texto con los hallazgos.
    """

    # Crear carpeta si no existe
    os.makedirs("reports", exist_ok=True)

    safe_url = url.replace("https://", "").replace("http://", "")
    safe_url = safe_url.replace("/", "_").replace(".", "_")
    
    safe_timestamp = timestamp.replace(":", "-").replace(" ", "_")
    
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    filename = f"security_report_{safe_url}_{safe_timestamp}.txt"
    filepath = os.path.join(REPORTS_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as file:
        file.write(f"URL: {url}\n\n")
        file.write(f"Timestamp: {timestamp}\n\n")
        file.write("=== HALLAZGOS ===\n\n")

        for finding in findings:
            severity = finding["severity"]
            header = finding["header"]
            status = finding["status"]
            description = finding["description"]
            recommendation = finding["recommendation"]

            if status == "present":
                file.write(f"[OK] {header} → presente\n")
                file.write(f"Función: {description}\n\n")
            elif status == "missing":
                file.write(f"[{severity}] {header} → no encontrado\n")
                file.write(f"Riesgo: {description}\n")
                file.write(f"Recomendación: {recommendation}\n\n")
            elif status == "exposed":
                file.write(f"[{severity}] {header} → expuesto\n")
                file.write(f"Riesgo: {description}\n")
                file.write(f"Recomendación: {recommendation}\n\n")

        file.write("=== RESUMEN ===\n")
        file.write(f"TOTAL:  {summary['total']}\n")
        file.write(f"HIGH:   {summary['HIGH']}\n")
        file.write(f"MEDIUM: {summary['MEDIUM']}\n")
        file.write(f"LOW:    {summary['LOW']}\n")
        file.write(f"OK:     {summary['OK']}\n")

    print(f"\n[INFO] Reporte generado: {filename}")

def generate_json_report(url, findings, summary, timestamp):
    """
    Genera un reporte en formato JSON con los hallazgos.
    """
    json_summary = {
    "total": summary["total"],
    "high": summary["HIGH"],
    "medium": summary["MEDIUM"],
    "low": summary["LOW"],
    "ok": summary["OK"]
    }
    
    report_data = {
        "url": url,
        "timestamp": timestamp,
        "findings": findings,
        "summary": json_summary
    }

    safe_url = url.replace("https://", "").replace("http://", "")
    safe_url = safe_url.replace("/", "_").replace(".", "_")

    safe_timestamp = timestamp.replace(":", "-").replace(" ", "_")

    filename = f"security_report_{safe_url}_{safe_timestamp}.json"
    filepath = os.path.join(REPORTS_DIR, filename)

    os.makedirs(REPORTS_DIR, exist_ok=True)

    with open(filepath, "w", encoding="utf-8") as file:
        json.dump(report_data, file, indent=4)

    print(f"[INFO] JSON generado: {filepath}")