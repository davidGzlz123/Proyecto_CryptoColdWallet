# app/nonce_manager.py
# Módulo de manejo de Nonces [Persistencia Anti-Replay].
# Se encarga de guardar el contador de transacciones de cada dirección en un JSON.

import json
import os

# Archivo donde guardaremos el estado de los nonces (nuestra "Base de Datos")
NONCE_DB_PATH = "nonce_db.json"

# Función encargada de leer la base de datos de nonces
def _load_db() -> dict:
    # Si el archivo no existe, retornamos un dict vacío
    if not os.path.exists(NONCE_DB_PATH):
        return {}
    
    try:
        with open(NONCE_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        # Si el archivo está corrupto o vacío, mejor empezamos de cero
        return {}

# Función encargada de guardar la base de datos de nonces 
def _save_db(data: dict):
    with open(NONCE_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

# Getter para el nonce de una dirección
def get_nonce(address: str) -> int:
    db = _load_db()
    # Si la dirección no existe en la DB, devuelve 0 por default
    return db.get(address, 0)

# Función para incrementar el nonce de una dirección
def increment_nonce(address: str):
    # Leemos el estado actual de la DB
    db = _load_db()
    
    # Obtenemos el valor actual, teniendo 0 si es nuevo
    current_nonce = db.get(address, 0)
    
    # incrementamos en 1
    db[address] = current_nonce + 1
    
    # Guardamos el estado actualizado
    _save_db(db)

# Función para validar el nonce de una transacción entrante
def validate_nonce(address: str, tx_nonce: int):

    # Primero, obtenemos el nonce esperado para esa dirección
    expected = get_nonce(address)
    
    # Si el nonce de la transacción es menor o mayor al esperado, lanzamos error
    if tx_nonce < expected:
        raise ValueError(f"Nonce inválido: {tx_nonce}. Es menor al esperado ({expected}). Posible Replay Attack.")
    
    # Si el nonce es mayor, también es inválido
    if tx_nonce > expected:
        raise ValueError(f"Nonce inválido: {tx_nonce}. Es mayor al esperado ({expected}). Transacción fuera de orden.")
    
    # Si no hubo errores, el nonce es válido
    return True