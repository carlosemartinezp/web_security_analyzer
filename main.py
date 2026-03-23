import sys
from scanner.headers import analyze_headers

def main():
    """
    Punto de entrada del programa.
    """

    # Validamos que el usuario pase una URL
    if len(sys.argv) < 2:
        print("Uso: python main.py <URL>")
        return

    url = sys.argv[1]

    print(f"\n[INFO] Analizando: {url}")

    analyze_headers(url)


if __name__ == "__main__":
    main()