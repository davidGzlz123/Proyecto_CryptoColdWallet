import sys
import os
import json

# Importamos funciones de tus módulos
from tools.create_keystore import main as create_keystore_main
from app.keystore import b64u_decode
from app.address import address_from_pubkey

# Ruta a la raíz del proyecto (carpeta Proyecto_CryptoColdWallet)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYSTORE_FILENAME = "mi_keystore.json"


def wallet_init():
    """
    Comando:
        python3 -m app wallet init

    Llama directamente a tu herramienta CLI existente:
        tools/create_keystore.py
    """
    create_keystore_main()


def wallet_address():
    """
    Comando:
        python3 -m app wallet address

    Lee mi_keystore.json desde la raíz del proyecto,
    extrae la pubkey en base64-url, la decodifica y deriva la dirección.
    """
    keystore_path = os.path.join(PROJECT_ROOT, KEYSTORE_FILENAME)

    if not os.path.exists(keystore_path):
        print(f"Error: no se encontró el keystore en: {keystore_path}")
        print("Primero ejecuta: python3 -m app wallet init")
        sys.exit(1)

    # Cargar keystore.json
    try:
        with open(keystore_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error al leer el keystore JSON: {e}")
        sys.exit(1)

    # Intentamos obtener la pubkey en base64-url
    # Ajusta el nombre del campo si es necesario (según tu make_keystore)
    pubkey_b64u = data.get("pubkey") or data.get("pubkey_b64u")

    if not pubkey_b64u:
        print("Error: el keystore no contiene un campo 'pubkey' ni 'pubkey_b64u'.")
        sys.exit(1)

    # Decodificar la pubkey
    try:
        pubkey_bytes = b64u_decode(pubkey_b64u)
    except Exception as e:
        print(f"Error: no se pudo decodificar la pubkey en base64-url: {e}")
        sys.exit(1)

    if len(pubkey_bytes) != 32:
        print(f"Error: la llave pública debe ser de 32 bytes; se obtuvieron {len(pubkey_bytes)}.")
        sys.exit(1)

    # Derivar address
    try:
        address = address_from_pubkey(pubkey_bytes)
    except Exception as e:
        print(f"Error al derivar la dirección desde la pubkey: {e}")
        sys.exit(1)

    print("-" * 40)
    print(f"Pubkey (b64u): {pubkey_b64u}")
    print(f"Dirección:     {address}")
    print("-" * 40)


def main():
    """
    Punto de entrada de:
        python3 -m app ...
    """
    if len(sys.argv) < 2:
        print("Uso: python3 -m app wallet <comando>")
        print("Comandos disponibles: wallet")
        sys.exit(1)

    group = sys.argv[1]

    if group != "wallet":
        print(f"Grupo desconocido: {group}")
        print("Por ahora solo se soporta: wallet")
        sys.exit(1)

    if len(sys.argv) < 3:
        print("Uso: python3 -m app wallet <init|address>")
        sys.exit(1)

    cmd = sys.argv[2]

    if cmd == "init":
        wallet_init()
    elif cmd == "address":
        wallet_address()
    else:
        print(f"Comando desconocido para 'wallet': {cmd}")
        print("Comandos soportados: init, address")
        sys.exit(1)


if __name__ == "__main__":
    main()
