import sys
from scanner.headers import analyze_headers

# Define el orden de prioridad de las severidades
SEVERITY_ORDER = {
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "OK": 4
}


def main():
    """
    Punto de entrada del programa.
    """
    if len(sys.argv) < 2:
        print("Uso: python main.py <URL>")
        return

    url = sys.argv[1]

    print(f"\n[INFO] Analizando: {url}")

    findings = analyze_headers(url)

    if findings is None:
        print("[INFO] No se pudieron obtener headers.")
        return

    # Ordenar hallazgos por severidad
    findings.sort(key=lambda finding: SEVERITY_ORDER[finding["severity"]])

    print("\n=== ANÁLISIS DE SEGURIDAD ===\n")

    summary = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "OK": 0
    }

    for finding in findings:
        severity = finding["severity"]
        header = finding["header"]
        status = finding["status"]
        description = finding["description"]
        recommendation = finding["recommendation"]

        summary[severity] += 1

        if status == "present":
            print(f"[OK] {header} → presente")
            print(f"     Función: {description}\n")
        elif status == "missing":
            print(f"[{severity}] {header} → no encontrado")
            print(f"     Riesgo: {description}")
            print(f"     Recomendación: {recommendation}\n")
        elif status == "exposed":
            print(f"[{severity}] {header} → expuesto")
            print(f"     Riesgo: {description}")
            print(f"     Recomendación: {recommendation}\n")

    print("=== RESUMEN ===")
    print(f"HIGH:   {summary['HIGH']}")
    print(f"MEDIUM: {summary['MEDIUM']}")
    print(f"LOW:    {summary['LOW']}")
    print(f"OK:     {summary['OK']}")
    

if __name__ == "__main__":
    main()