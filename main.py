import sys
from datetime import datetime
from scanner.headers import analyze_headers
from utils.report import generate_report, generate_json_report

# Define el orden de prioridad de las severidades
SEVERITY_ORDER = {"HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "OK": 5}


def main():
    """
    Punto de entrada del programa.
    """
    if len(sys.argv) < 2:
        print("Uso: python main.py <URL>")
        return

    url = sys.argv[1]
    if not url.startswith(("http://", "https://")):
        print("[ERROR] La URL debe comenzar con http:// o https://")
        sys.exit(1)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n[INFO] Analizando: {url}")

    findings = analyze_headers(url)

    if findings is None:
        print("[INFO] No se pudieron obtener headers.")
        return

    # Ordenar hallazgos por severidad
    findings.sort(key=lambda finding: SEVERITY_ORDER[finding["severity"]])

    print("\n=== ANÁLISIS DE SEGURIDAD ===\n")

    summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "OK": 0}

    summary["total"] = len(findings)

    for finding in findings:
        severity = finding["severity"]
        header = finding["header"]
        status = finding["status"]
        description = finding["description"]
        recommendation = finding["recommendation"]

        summary[severity] += 1

        if severity == "OK":
            print(f"[OK] {header} → {status}")
            print(f"     Función: {description}\n")
        else:
            print(f"[{severity}] {header} → {status}")
            print(f"     Hallazgo: {description}")
            print(f"     Recomendación: {recommendation}\n")

    print("=== RESUMEN ===")
    print(f"TOTAL:  {summary['total']}")
    print(f"HIGH:   {summary['HIGH']}")
    print(f"MEDIUM: {summary['MEDIUM']}")
    print(f"LOW:    {summary['LOW']}")
    print(f"INFO:   {summary['INFO']}")
    print(f"OK:     {summary['OK']}")

    generate_report(url, findings, summary, timestamp)
    generate_json_report(url, findings, summary, timestamp)


if __name__ == "__main__":
    main()
