# Web Security Analyzer

Herramienta CLI en Python para analizar headers HTTP de seguridad y generar un reporte con hallazgos, riesgos y recomendaciones.

---

## 🚀 Características

- Análisis de headers de seguridad:
  - Strict-Transport-Security
  - Content-Security-Policy
  - X-Frame-Options
  - X-Content-Type-Options
- Detección de exposición del header `Server`
- Clasificación de severidad:
  - HIGH
  - MEDIUM
  - LOW
  - OK
- Ordenamiento de hallazgos por severidad
- Generación de resumen
- Exportación de reporte en archivo `.txt`

---

## 🛠️ Tecnologías

- Python
- requests

---

## ⚙️ Instalación

```bash
python -m venv venv
venv\Scripts\activate
pip install requests
```

---

## ▶️ Uso

```bash
python main.py https://example.com
```

---

## 📄 Ejemplo de salida

```text
[HIGH] Content-Security-Policy → no encontrado
Riesgo: Ayuda a prevenir ataques XSS
Recomendación: Definir una política CSP...

[OK] X-Frame-Options → presente

=== RESUMEN ===
HIGH: 1
MEDIUM: 1
LOW: 1
OK: 1
```

---

## 📁 Estructura del proyecto

```text
web_security_analyzer/
│
├── main.py
├── scanner/
│   └── headers.py
├── utils/
│   ├── http_client.py
│   └── report.py
├── reports/
├── project_context.md
└── README.md
```
