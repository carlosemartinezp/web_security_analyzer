from utils.http_client import get_headers

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Protege contra ataques downgrade HTTP y fuerza HTTPS",
        "severity": "HIGH"
    },
    "Content-Security-Policy": {
        "description": "Ayuda a prevenir ataques XSS y carga de contenido no confiable",
        "severity": "HIGH"
    },
    "X-Frame-Options": {
        "description": "Protege contra ataques de clickjacking",
        "severity": "MEDIUM"
    },
    "X-Content-Type-Options": {
        "description": "Evita que el navegador interprete archivos con un tipo MIME incorrecto",
        "severity": "MEDIUM"
    }
}


def analyze_headers(url):
    """
    Analiza los headers de seguridad de una URL.
    Muestra cuáles están presentes, cuáles faltan
    y alerta si el servidor expone información sensible.
    """
    headers = get_headers(url)

    if headers is None:
        print("[INFO] No se pudieron obtener headers.")
        return

    print("\n=== ANÁLISIS DE SEGURIDAD ===\n")

    for header, info in SECURITY_HEADERS.items():
        description = info["description"]
        severity = info["severity"]

        if header in headers:
            print(f"[OK] {header} → presente")
            print(f"     Función: {description}\n")
        else:
            print(f"[{severity}] {header} → NO encontrado")
            print(f"     Riesgo: {description}\n")

    if "Server" in headers:
        print(f"[LOW] Server expuesto → {headers['Server']}")
        print("     Riesgo: exposición de información sobre la tecnología del servidor\n")