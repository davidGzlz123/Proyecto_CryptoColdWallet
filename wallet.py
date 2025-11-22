#!/usr/bin/env python3
# CLI interactiva de la Crypto Cold Wallet 

import argparse
import sys
import os
import json
import getpass
import shutil
import time

# --- Importaciones del Proyecto ---
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.keystore import generate_ed25519_keypair, make_keystore, save_keystore, load_keystore, decrypt_private_key
from app.address import address_from_pubkey
from app.signer import Signer
from app.verifier import Verifier
from app.keystore import b64u_decode # Necesario para decodificar la pubkey

# --- Configuración de Directorios ---
OUTBOX_DIR = "outbox"
INBOX_DIR = "inbox"
VERIFIED_DIR = "verified"
REJECTED_DIR = "rejected"

# --- Utilidades de Directorios ---
def ensure_dirs():
    for d in [OUTBOX_DIR, INBOX_DIR, VERIFIED_DIR, REJECTED_DIR]:
        os.makedirs(d, exist_ok=True)

# --- Lógica de Comandos ---

# Función para crear un nuevo keystore 
def interactive_init():
    print("\n--- 1. Crear Nueva Wallet ---")
    filename = input("Nombre del archivo [default: keystore.json]: ").strip() or "keystore.json"
    
    # Si al usuario se le olvidó la extensión, se la ponemos
    if not filename.endswith(".json"):
        filename += ".json"
        print(f"💡 Nota: Se agregó la extensión '.json' automáticamente -> {filename}")
        
    pass1 = getpass.getpass("Nueva Passphrase: ")
    pass2 = getpass.getpass("Confirma Passphrase: ")
    
    if pass1 != pass2:
        print("Error: Las passphrases no coinciden.")
        return

    if len(pass1) < 8:
        print("Advertencia: La passphrase es muy corta (mínimo 8 caracteres).")

    print("Generando llaves...")
    priv, pub = generate_ed25519_keypair()
    ks = make_keystore(priv, pub, pass1)
    save_keystore(filename, ks)
    
    addr = address_from_pubkey(pub)
    print(f"\n¡Keystore guardado en '{filename}'!")
    print(f"Dirección: {addr}")

# Función para mostrar la dirección desde un keystore existente
def interactive_address():
    print("\n--- 2. Ver Dirección ---")
    filename = input("Archivo keystore [default: keystore.json]: ").strip() or "keystore.json"
    # Intentamos cargar el keystore y derivar la dirección
    try:
        ks = load_keystore(filename)
        pub_bytes = b64u_decode(ks["pubkey"])
        addr = address_from_pubkey(pub_bytes)
        print(f"\nDirección: {addr}")
    except Exception as e:
        print(f"Error al leer keystore: {e}")

# Función para firmar una transacción y guardarla en outbox/
def interactive_sign():
    print("\n--- 3. Firmar Transacción ---")
    ensure_dirs()
    
    # Obtenemos los datos necesarios del keystore 
    filename = input("Archivo keystore [default: keystore.json]: ").strip() or "keystore.json"
    try:
        ks = load_keystore(filename)
    except Exception as e:
        print(f"No se encontró el archivo: {e}")
        return
    
    # Obtenemos los datos de la Transacción a firmar
    print("\n--- Detalles de la Transacción ---")
    to_addr = input("Destino (0x...): ").strip()
    if not to_addr.startswith("0x"):
        to_addr = "0x" + to_addr
        print(f"💡 Nota: Se agregó el prefijo '0x' automáticamente -> {to_addr}")
    try:
        amount = int(input("Monto (entero): ").strip())
    except ValueError:
        print("El monto debe ser un número.")
        return

    # Autenticamos al usuario para desencriptar la llave privada
    passphrase = getpass.getpass(f"\nPassphrase para '{filename}': ")
    
    try:
        priv_pem = decrypt_private_key(ks["crypto"], passphrase)
    except Exception as e:
        print(f"Error de autenticación: {e}")
        return

    # Construimos la transacción a firmar
    my_pub = b64u_decode(ks["pubkey"])
    my_address = address_from_pubkey(my_pub)

    tx = {
        "from": my_address,
        "to": to_addr,
        "value": amount,
        "nonce": int(time.time())
    }
    
    print(f"\nFirmando transacción: {json.dumps(tx, indent=2)}")

    # Firma de la transacción
    try:
        signed_tx = Signer.sign(tx, priv_pem)
    except Exception as e:
        print(f"Error al firmar: {e}")
        return

    # Aalmacenamos la transacción firmada en outbox/
    tx_filename = f"tx_{signed_tx['signature'][:8]}.json"
    out_path = os.path.join(OUTBOX_DIR, tx_filename)
    
    with open(out_path, 'w') as f:
        json.dump(signed_tx, f, indent=2)
    
    print(f"\n✅ Firmada y guardada en: {out_path}")

    # Opcional: Preguntamos si se quiere enviar la transacción a inbox/ automáticamente
    print("-" * 30)
    auto_send = input("¿Quieres transmitir a la red (Inbox) ahora? [s/n]: ").lower()
    if auto_send == 's':
        dst_path = os.path.join(INBOX_DIR, tx_filename)
        shutil.copy(out_path, dst_path)
        print(f"Transacción enviada a: {dst_path}")
        print("Listo para procesar.")
    else:
        print("Ok, se quedó en outbox/.")

# Función para procesar transacciones en inbox/
def interactive_process():
    print("\n--- 4. Procesar Red (Simulación) ---")
    ensure_dirs()
    
    files = [f for f in os.listdir(INBOX_DIR) if f.endswith('.json')]
    if not files:
        print("La Inbox está vacía.")
        return

    print(f"Procesando {len(files)} transacciones pendientes...\n")
    
    for filename in files:
        src = os.path.join(INBOX_DIR, filename)
        print(f" > Verificando: {filename} ... ", end="")
        
        try:
            with open(src, 'r') as f:
                signed_tx = json.load(f)
            
            is_valid, msg = Verifier.verify(signed_tx)
            
            if is_valid:
                dst = os.path.join(VERIFIED_DIR, filename)
                shutil.move(src, dst)
                print(f"[OK] -> Verified")
            else:
                dst = os.path.join(REJECTED_DIR, filename)
                shutil.move(src, dst)
                print(f"[INVALIDO: {msg}] -> Rejected")
                
        except Exception as e:
            dst = os.path.join(REJECTED_DIR, filename)
            shutil.move(src, dst)
            print(f"[ERROR: {e}] -> Rejected")


# --- Menú Principal CLI ---
def main_menu():
    while True:
        print("\n" + "="*30)
        print("   CRYPTO COLD WALLET CLI")
        print("="*30)
        print("1. Crear Wallet (Init)")
        print("2. Ver Dirección (Address)")
        print("3. Firmar Transacción (Sign)")
        print("4. Procesar Red (Process Inbox)")
        print("0. Salir")
        
        opcion = input("\nElige una opción: ").strip()
        
        if opcion == '1':
            interactive_init()
        elif opcion == '2':
            interactive_address()
        elif opcion == '3':
            interactive_sign()
        elif opcion == '4':
            interactive_process()
        elif opcion == '0':
            print("Bye! 👋👋👋")
            break
        else:
            print("Opción no válida.")

# --- Entry Point Híbrido ---
# Soporta tanto argumentos (para scripts) como modo interactivo (para humanos)

def main():
    parser = argparse.ArgumentParser(description="Crypto Cold Wallet CLI")
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")

    # Definimos argumentos opcionales para mantener compatibilidad con scripts
    # ... (Init)
    p_init = subparsers.add_parser("init")
    p_init.add_argument("--filename", default="keystore.json")

    # ... (Address)
    p_addr = subparsers.add_parser("address")
    p_addr.add_argument("--keystore", default="keystore.json")

    # ... (Sign)
    p_sign = subparsers.add_parser("sign")
    p_sign.add_argument("--keystore", default="keystore.json")
    p_sign.add_argument("--to", help="Dirección destino")
    p_sign.add_argument("--amount", type=int, help="Monto")

    # ... (Process)
    p_proc = subparsers.add_parser("process")

    # Si no hay argumentos, lanzamos el menú interactivo
    if len(sys.argv) == 1:
        main_menu()
    else:
        # Si hay argumentos, usamos la lógica vieja (o adaptada) para scripts
        # (Por brevedad, aquí redirigimos a las funciones interactivas si faltan datos,
        #  o podrías mantener la lógica estricta anterior).
        args = parser.parse_args()
        if args.command == "process":
            interactive_process()
        # ... Para los otros, si faltan args, el parser se quejará o podrías adaptarlo.
        # Por ahora, el modo menú es el rey.

if __name__ == "__main__":
    main()