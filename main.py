import sys
from scanner.headers import analyze_headers

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

    print("\n=== ANÁLISIS DE SEGURIDAD ===\n")

    for finding in findings:
        severity = finding["severity"]
        header = finding["header"]
        status = finding["status"]
        description = finding["description"]
        recommendation = finding["recommendation"]

        if status == "present":
            print(f"[OK] {header} → presente")
            print(f"     Función: {description}\n")
        else:
            print(f"[{severity}] {header} → {status}")
            print(f"     Riesgo: {description}")
            print(f"     Recomendación: {recommendation}\n")


if __name__ == "__main__":
    main()