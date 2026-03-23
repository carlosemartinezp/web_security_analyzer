import requests

def get_headers(url):
    """
    Realiza una petición HTTP a la URL dada y retorna los headers.

    :param url: URL a analizar
    :return: diccionario de headers o None si falla
    """
    try:
        response = requests.get(url, timeout=5)

        # response.headers es como un diccionario
        return response.headers

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] No se pudo conectar a {url}")
        print(f"Detalle: {e}")
        return None