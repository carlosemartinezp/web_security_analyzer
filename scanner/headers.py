from utils.http_client import get_headers

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Protege contra ataques downgrade HTTP y fuerza HTTPS",
        "severity": "HIGH",
        "recommendation": "Configurar HSTS para forzar conexiones HTTPS seguras."
    },
    "Content-Security-Policy": {
        "description": "Ayuda a prevenir ataques XSS y carga de contenido no confiable",
        "severity": "HIGH",
        "recommendation": "Definir una política CSP que restrinja scripts, estilos y recursos a orígenes confiables."
    },
    "X-Frame-Options": {
        "description": "Protege contra ataques de clickjacking",
        "severity": "MEDIUM",
        "recommendation": "Agregar X-Frame-Options con valor DENY o SAMEORIGIN según el caso."
    },
    "X-Content-Type-Options": {
        "description": "Evita que el navegador interprete archivos con un tipo MIME incorrecto",
        "severity": "MEDIUM",
        "recommendation": "Agregar X-Content-Type-Options con el valor nosniff."
    }
}


def analyze_headers(url):
    """
    Analiza los headers de seguridad de una URL y retorna
    una lista de hallazgos.
    """
    headers = get_headers(url)

    if headers is None:
        return None

    findings = []

    for header, info in SECURITY_HEADERS.items():
        description = info["description"]
        severity = info["severity"]
        recommendation = info["recommendation"]

        if header in headers:
            findings.append({
                "header": header,
                "status": "present",
                "severity": "OK",
                "description": description,
                "recommendation": "No se requiere acción."
            })
        else:
            findings.append({
                "header": header,
                "status": "missing",
                "severity": severity,
                "description": description,
                "recommendation": recommendation
            })

    if "Server" in headers:
        findings.append({
            "header": "Server",
            "status": "exposed",
            "severity": "LOW",
            "description": f"El servidor expone el valor: {headers['Server']}",
            "recommendation": "Ocultar o minimizar el valor del header Server si es posible."
        })

    return findings