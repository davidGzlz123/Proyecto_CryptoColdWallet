# Herramienta CLI para firmar una transacción usando el keystore JSON.

import os
import sys
import json
import getpass

# Ajustar el path para poder importar 'app'
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)

from app.keystore import load_keystore, decrypt_private_key, b64u_decode
from app.transaction import make_tx, tx_canonical_bytes
from app.signer import Signer


def load_tx_from_file(path: str) -> dict:
    """
    Carga una transacción desde un archivo JSON.
    Espera un JSON con campos: from, to, value, nonce (y opcional data).
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Aquí asumimos que el archivo ya trae esos campos.
    # se pueden validar mas
    return data


def main():
    if len(sys.argv) < 3:
        print("Uso:")
        print(f"  python tools/sign_tx.py <ruta_tx.json> <output_signed.json>")
        sys.exit(1)

    tx_path = sys.argv[1]
    out_path = sys.argv[2]

    # 1. Cargar keystore
    keystore_path = os.path.join(project_root, "mi_keystore.json")
    if not os.path.exists(keystore_path):
        print(f"ERROR: No se encontró el keystore en {keystore_path}")
        sys.exit(1)

    print(f"Usando keystore: {keystore_path}")
    ks = load_keystore(keystore_path)

    # 2. Pedir passphrase
    passphrase = getpass.getpass("Passphrase del keystore: ")

    try:
        # Desbloquear la private key PEM
        pem = decrypt_private_key(ks["crypto"], passphrase)
    except ValueError as e:
        print(f"ERROR al desencriptar la llave privada: {e}")
        sys.exit(1)

    # 3. Cargar la transacción desde el archivo
    if not os.path.exists(tx_path):
        print(f"ERROR: No se encontró el archivo de transacción: {tx_path}")
        sys.exit(1)

    raw_tx = load_tx_from_file(tx_path)

    # 4. Construir la tx con make_tx (valida tipos y campos)
    try:
        tx = make_tx(
            sender=raw_tx["from"],
            to=raw_tx["to"],
            value=int(raw_tx["value"]),
            nonce=int(raw_tx["nonce"]),
            data=raw_tx.get("data"),
        )
    except KeyError as e:
        print(f"ERROR: Falta el campo obligatorio en la tx: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"ERROR en los valores de la transacción: {e}")
        sys.exit(1)

    # 5. Mostrar representación canónica (opcional, debug)
    canon = tx_canonical_bytes(tx)
    print("Transacción canónica (bytes):")
    print(canon.decode("utf-8"))

    # 6. Firmar la transacción
    signed = Signer.sign(tx, pem)

    # 7. Guardar en archivo de salida
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(signed, f, indent=2, ensure_ascii=False)

    print("-" * 40)
    print("¡Transacción firmada con éxito!")
    print(f"Archivo de salida: {out_path}")
    print("-" * 40)


if __name__ == "__main__":
    main()
