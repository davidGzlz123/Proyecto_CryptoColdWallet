# Herramienta CLI para verificar una transacción firmada en JSON.
#
# Flujo:
#   1. Lee un archivo JSON con la estructura:
#        {
#          "tx": { ... },
#          "signature": "<firma_base64url>",
#          "pubkey": "<pubkey_base64url>",
#          "scheme": "ed25519"
#        }
#   2. Obtiene los bytes canónicos de la tx (tx_canonical_bytes).
#   3. Decodifica firma y pubkey desde Base64-URL.
#   4. Reconstruye la llave pública Ed25519.
#   5. Verifica la firma:
#        - Si es válida → transacción íntegra.
#        - Si no → posible tampering o firma incorrecta.

import os
import sys
import json

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)

from app.transaction import tx_canonical_bytes
from app.keystore import b64u_decode
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def load_signed_tx(path: str) -> dict:
    """
    Carga desde disco un JSON de transacción firmada.
    No valida todavía la estructura; solo parsea el JSON.
    """
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    # Validación de argumentos
    if len(sys.argv) < 2:
        print("Uso:")
        print("  python tools/verify_tx.py <tx_firmada.json>")
        sys.exit(1)

    signed_path = sys.argv[1]

    if not os.path.exists(signed_path):
        print(f"ERROR: No se encontró el archivo: {signed_path}")
        sys.exit(1)

    # 1. Cargar el JSON firmado desde disco
    try:
        signed = load_signed_tx(signed_path)
    except Exception as e:
        print(f"ERROR al leer JSON firmado: {e}")
        sys.exit(1)

    # 2. Validar que existan los campos mínimos esperados
    for f in ["tx", "signature", "pubkey", "scheme"]:
        if f not in signed:
            print(f"ERROR: falta el campo obligatorio '{f}' en el JSON firmado")
            sys.exit(1)

    # Verificamos el esquema de firma
    if signed["scheme"] != "ed25519":
        print("ERROR: esquema no soportado:", signed["scheme"])
        sys.exit(1)

    tx = signed["tx"]
    sig_b64 = signed["signature"]
    pub_b64 = signed["pubkey"]

    # 3. Obtener bytes canónicos de la transacción
    try:
        canon = tx_canonical_bytes(tx)
    except Exception as e:
        print("ERROR al canonicalizar la transacción:", e)
        sys.exit(1)

    # 4. Decodificar firma y pubkey desde Base64-URL
    try:
        sig = b64u_decode(sig_b64)
        pub_bytes = b64u_decode(pub_b64)
    except Exception:
        print("ERROR: firma o pubkey con Base64 inválido")
        sys.exit(1)

    # 5. Reconstruir la llave pública de Ed25519
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except Exception:
        print("ERROR: pubkey inválida")
        sys.exit(1)

    # 6. Verificar la firma
    try:
        pub.verify(sig, canon)
        print("✅ Firma VÁLIDA: la transacción coincide con la firma y la pubkey.")
        sys.exit(0)
    except Exception:
        print("❌ Firma INVÁLIDA: posible tampering o firma incorrecta.")
        sys.exit(2)


if __name__ == "__main__":
    main()
