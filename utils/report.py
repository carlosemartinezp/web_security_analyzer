import os

def generate_report(url, findings, summary):
    """
    Genera un reporte en archivo de texto con los hallazgos.
    """

    # Crear carpeta si no existe
    os.makedirs("reports", exist_ok=True)

    filename = "reports/security_report.txt"

    with open(filename, "w", encoding="utf-8") as file:
        file.write(f"URL: {url}\n\n")
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
        file.write(f"HIGH:   {summary['HIGH']}\n")
        file.write(f"MEDIUM: {summary['MEDIUM']}\n")
        file.write(f"LOW:    {summary['LOW']}\n")
        file.write(f"OK:     {summary['OK']}\n")

    print(f"\n[INFO] Reporte generado: {filename}")