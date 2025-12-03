# app/address.py
# Módulo dedicado a sacar la dirección (address) de la llave pública.
# Decidimos usar SHA-256, que es nativo en Python

import hashlib 


# Función que recibe 32 bytes de la llave pública de Ed25519 y regresa 
# la "dirección" en formato hexadecimal
def address_from_pubkey(pubkey_bytes: bytes) -> str:
    
    # Primero, revisamos que la llave pública sea válida con 32 bytes
    if not isinstance(pubkey_bytes, bytes) or len(pubkey_bytes) != 32:
        raise ValueError(f"La llave pública debe ser de 32 bytes, pero me diste {len(pubkey_bytes)}")

    # Hacemos el hash SHA-256 
    hash_bytes = hashlib.sha256(pubkey_bytes).digest() # Saca 32 bytes de hash

    # Se consigue la dirreción con los últimos 20 bytes de ese hash
    address_bytes = hash_bytes[-20:]
    
    # Pasamos la dirección a hexadecimal
    address_hex = address_bytes.hex()
    
    # Le ponemos al inicio '0x' y la regresamos
    return "0x" + address_hex