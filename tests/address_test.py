# tests/test_address.py
# Pruebas unitarias para el módulo de direcciones con sha256

import os
import pytest
import sys
# Obtiene la ruta absoluta de la carpeta 'tests' (donde está este archivo)
current_dir = os.path.dirname(os.path.abspath(__file__))
# Sube un nivel para llegar a la raíz del proyecto ('Proyecto_CryptoColdWallet')
project_root = os.path.dirname(current_dir)
# Añade la raíz del proyecto al path de búsqueda de Python
sys.path.insert(0, project_root)
from app.address import address_from_pubkey

# Test 1: Prueba de determinismo, enfocada en asegurar que con una
# misma llave pública, siemre se debe de conseguir la misma dirección.
def test_determinismo():
    pubkey = os.urandom(32) # Una pubkey X
    addr1 = address_from_pubkey(pubkey)
    addr2 = address_from_pubkey(pubkey)
    assert addr1 == addr2 # Deben ser idénticas

# Test 2: Prueba de formato de la dirección
# Revisamos que la dirección tenga el formato "0x..." y 40 caracteres hexadecimales
def test_formato_hex():
    pubkey = os.urandom(32)
    addr = address_from_pubkey(pubkey)
    
    # Se asegura que la dirección empiece con 0x
    assert addr.startswith("0x")
    
    # Se confirma que la dirección tenga 42 caracteres en total
    # 0x de inicio y 20 bytes * 2 caracteres hexa por byte, siendo así los otros 42
    assert len(addr) == 42
    
    # Revisamos que sea un hexadecimal válido (después del '0x')
    try:
        int(addr, 16)
    except ValueError:
        pytest.fail("La dirección no es un hexadecimal válido.")

# Test 3 (Golden Vector):
# Probamos con una dirección conocida que la llave pública derivada
# sea igual a dicha dirección 
def test_golden_vector():
    # Usamos una llave pública de 32 bytes de puros ceros
    pubkey_bytes = b'\x00' * 32
    
    # El 'golden vector' para SHA-256(b'\x00'*32) es este:
    # Hash (completo, 32 bytes):
    # '8e9f8e20089714856ee233b3902a591d0d5f2925f82912583b6d63606f4b8028'
    # Últimos 20 bytes (40 chars):
    expected_address = "0x8e9f8e20089714856ee233b3902a591d0d5f2925"
    
    # Corremos nuestra función
    addr = address_from_pubkey(pubkey_bytes)
    
    # Si hay fallo, nuestra lógica de 'slice' está mal
    print(addr)
    assert addr == expected_address