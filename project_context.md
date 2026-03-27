# Proyecto: Web Security Analyzer

## Objetivo
Analizar headers HTTP de seguridad en una URL y generar un reporte con hallazgos, riesgos y recomendaciones.

## Stack
- Python
- requests

## Funcionalidades actuales
- CLI que recibe una URL
- Realiza petición HTTP
- Obtiene headers de respuesta
- Analiza headers de seguridad:
  - Strict-Transport-Security
  - Content-Security-Policy
  - X-Frame-Options
  - X-Content-Type-Options
- Detecta exposición del header Server
- Clasifica hallazgos por severidad:
  - HIGH
  - MEDIUM
  - LOW
  - OK
- Ordena resultados por severidad
- Genera resumen de hallazgos
- Exporta reporte en archivo TXT

## Estructura del proyecto
- main.py → punto de entrada (CLI)
- scanner/headers.py → lógica de análisis
- utils/http_client.py → petición HTTP
- utils/report.py → generación de reporte

## Estado actual
- Versión 1 casi terminada
- Herramienta funcional en CLI
- Generación de reporte en TXT implementada

## Decisiones técnicas
- Separación de responsabilidades (análisis vs output)
- Uso de diccionarios para definir reglas de seguridad
- Uso de lista de findings para estructurar resultados
- Ordenamiento por severidad usando mapeo numérico

## Próximos pasos
- Exportar resultados a JSON
- Validación básica de URL
- Crear README para el repositorio
- Iniciar versión en Java basada en esta lógica