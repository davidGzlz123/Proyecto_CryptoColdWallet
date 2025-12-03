# tools/get_address.py
# Se implementa una herramienta complementaria CLI para 
# obtener una dirección desde una pubkey.
#
# Uso:
# 1. Copia la 'pubkey' (el string b64u) de tu keystore.json.
# 2. Corre desde la RAÍZ del proyecto:
#    python tools/get_address.py <pubkey_b64u_string>

import sys
import os

# Nos aseguramos que el path al módulo 'app' esté en sys.path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)


try:
    # Importamos nuestros módulos 
    from app.address import address_from_pubkey
    from app.keystore import b64u_decode 
except ImportError as e:
    print(f"Error: No se pudieron importar los módulos de 'app'. Asegúrate de tener '{project_root}/app' en tu PYTHONPATH.")
    print(f"Detalle: {e}")
    sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print(f"Uso: python {sys.argv[0]} <pubkey_b64u_string>")
        print("\n (La 'pubkey_b64u_string' se encuentra en el campo 'pubkey' del 'keystore.json')")
        sys.exit(1)
        
    pubkey_b64u = sys.argv[1]
    
    try:
        # Se realiza la decodificación de la llave pública
        pubkey_bytes = b64u_decode(pubkey_b64u)
    except Exception:
        print("Error: String Base64-URLSafe inválido.")
        sys.exit(1)
    # Realizamos la verificación del tamaño de la llave pública
    if len(pubkey_bytes) != 32:
        print(f"Error: La llave pública decodificada debe ser de 32 bytes, pero se recibieron {len(pubkey_bytes)}.")
        sys.exit(1)
    
    # En base a la llave pública, derivamos la dirección
    address = address_from_pubkey(pubkey_bytes)
    
    print("-" * 40) 
    print(f"Pubkey (b64u): {pubkey_b64u}")
    print(f"Dirección:     {address}")
    print("-" * 40)

if __name__ == "__main__":
    main()