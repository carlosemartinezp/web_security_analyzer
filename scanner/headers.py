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

def analyze_hsts(headers):
    """
    Analiza la configuración del header Strict-Transport-Security.
    """

    header_name = "Strict-Transport-Security"

    if header_name not in headers:
        return {
            "header": header_name,
            "status": "missing",
            "severity": "HIGH",
            "description": "HSTS no está configurado.",
            "recommendation": "Configurar Strict-Transport-Security con max-age de al menos 31536000 segundos."
        }

    hsts_value = headers[header_name].lower()

    if "max-age=" not in hsts_value:
        return {
            "header": header_name,
            "status": "misconfigured",
            "severity": "MEDIUM",
            "description": f"HSTS está presente pero no define max-age: {headers[header_name]}",
            "recommendation": "Agregar max-age al header HSTS. Valor recomendado: 31536000 segundos o superior."
        }

    max_age_part = hsts_value.split("max-age=")[1].split(";")[0].strip()

    try:
        max_age = int(max_age_part)
    except ValueError:
        return {
            "header": header_name,
            "status": "misconfigured",
            "severity": "MEDIUM",
            "description": f"HSTS define un max-age inválido: {headers[header_name]}",
            "recommendation": "Usar un valor numérico válido para max-age. Valor recomendado: 31536000 segundos o superior."
        }

    if max_age < 31536000:
        return {
            "header": header_name,
            "status": "weak",
            "severity": "MEDIUM",
            "description": f"HSTS está configurado con max-age bajo: {max_age} segundos.",
            "recommendation": "Aumentar max-age a por lo menos 31536000 segundos."
        }

    if "includesubdomains" not in hsts_value:
        return {
            "header": header_name,
            "status": "partial",
            "severity": "LOW",
            "description": f"HSTS tiene un max-age adecuado, pero no incluye includeSubDomains: {headers[header_name]}",
            "recommendation": "Agregar includeSubDomains si todos los subdominios soportan HTTPS correctamente."
        }

    if "preload" not in hsts_value:
        return {
            "header": header_name,
            "status": "informational",
            "severity": "INFO",
            "description": f"HSTS está bien configurado, pero no incluye preload: {headers[header_name]}",
            "recommendation": "Considerar preload solo si el dominio y todos sus subdominios soportan HTTPS de forma permanente."
        }

    return {
        "header": header_name,
        "status": "present",
        "severity": "OK",
        "description": f"HSTS está configurado correctamente con max-age adecuado e includeSubDomains: {max_age} segundos.",
        "recommendation": "No se requiere acción."
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
        if header == "Strict-Transport-Security":
            findings.append(analyze_hsts(headers))
            continue

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