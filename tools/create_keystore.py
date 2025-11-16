# tools/create_keystore.py
# Herramienta CLI para generar un archivo keystore.json 

import sys
import os
import getpass # Para pedir contraseñas de forma segura

# Sube 1 nivel a 'Proyecto_CryptoColdWallet'
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Añade la raíz del proyecto al path de búsqueda de Python
sys.path.insert(0, project_root)

try:
    # Importamos las funciones que necesitamos de nuestros módulos
    from app.keystore import generate_ed25519_keypair, make_keystore, save_keystore
    from app.address import address_from_pubkey
except ImportError as e:
    print(f"Error: No se pudieron importar los módulos de 'app'.")
    print(f"Detalle: {e}")
    sys.exit(1)


def main():
    print("--- Creando un nuevo Keystore (JSON) ---")
    
    # 1. Pedimos la passphrase o contraseña de forma segura
    passphrase = getpass.getpass("Ingresa una passphrase para el keystore: ")
    passphrase_confirm = getpass.getpass("Confirma la passphrase: ")
    
    if passphrase != passphrase_confirm:
        print("\nERROR: Las passphrases no coinciden. Abortando.")
        sys.exit(1)
        
    if not passphrase:
        print("\nERROR: La passphrase no puede estar vacía. Abortando.")

    print("\nGenerando llaves Ed25519...")
    # 2. Generamos el par de llaves
    priv_pem, pub_raw = generate_ed25519_keypair()
    print("Creando el diccionario keystore (cifrando llave)...")
    # 3. Creamos el objeto keystore para cifrar la llave privada
    ks = make_keystore(priv_pem, pub_raw, passphrase)
    # 4. Definimos dónde guardar el archivo
    output_filename = "mi_keystore.json"
    output_path = os.path.join(project_root, output_filename)
    # 5. Guardamos el archivo
    save_keystore(output_path, ks)
    print("-" * 40)
    print(f"¡ÉXITO! Keystore guardado en:")
    print(f"{output_path}")
    print("-" * 40)
    
    # 6. Mostramos la dirección pública
    address = address_from_pubkey(pub_raw)
    print(f"Tu dirección pública (Address) es: {address}")
    print(f"(Puedes usar 'tools/get_address.py' para verla de nuevo)")

if __name__ == "__main__":
    main()