# test_keygen.py
import sys
import os

# Obtiene la ruta absoluta de la carpeta 'tests' 
current_dir = os.path.dirname(os.path.abspath(__file__))
# Sube un nivel para llegar a la raíz del proyecto ('Proyecto_CryptoColdWallet')
project_root = os.path.dirname(current_dir)
# Añade la raíz del proyecto al path de búsqueda de Python
sys.path.insert(0, project_root)


import pytest
from app import keygen
import binascii

def test_keypair_generation_and_lengths():
    """
    Test 1: Verificación de que las llaves se generen y tengan el tamaño correcto.
    Ed25519 debe tener:
        - 32 bytes de llave privada (seed)
        - 32 bytes de llave pública
    """
    private_bytes, public_bytes = keygen.generate_keypair()
    
    # Verificación de tipos de datos bytes
    assert isinstance(private_bytes, bytes)
    assert isinstance(public_bytes, bytes)
    
    # Verificación de longitudes
    assert len(private_bytes) == 32
    assert len(public_bytes) == 32

def test_export_formats():
    """
    Test P1: Verifica que las funciones de exportación (hex/b64) funcionen.
    """
    # Usamos una llave simple: b'test'
    dummy_pub_key = b'test' # 4 bytes
    
    # Prueba Hex 
    hex_key = keygen.export_pubkey_hex(dummy_pub_key)
    # b't' = 74, b'e' = 65, b's' = 73, b't' = 74
    expected_hex = '74657374'
    assert hex_key == expected_hex
    
    # Prueba Base64 
    b64_key = keygen.export_pubkey_base64(dummy_pub_key)
    # b'test' en Base64 es 'dGVzdA=='
    expected_b64 = 'dGVzdA=='
    assert b64_key == expected_b64


def test_sign_verify_roundtrip():
    """
    Test 2: Verifica la integridad del par de llaves (Firmar -> Verificar).
    
    Un mensaje firmado con la llave privada debe de ser verificado
    exitosamente por la llave pública correspondiente.
    """
    private_bytes, public_bytes = keygen.generate_keypair()
    message = b"Este es un mensaje de prueba para el test de integridad P1"
    
    signature = b""
    
    # 1. FIRMA 
    if keygen.CRYPTOGRAPHY_OK:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        private_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
        signature = private_obj.sign(message)
        
    elif keygen.PYNACL_OK:
        from nacl.signing import SigningKey
        signing_key = SigningKey(private_bytes)
        signature = signing_key.sign(message).signature
        
    else:
        # Si no hay librerías, se fuerza el fallo del test
        pytest.fail("No se encontró biblioteca de crypto (cryptography o pynacl) para firmar")
        
    # La firma Ed25519 siempre debe ser de 64 bytes
    assert len(signature) == 64

    # 2. VERIFICACIÓN 
   
    if keygen.CRYPTOGRAPHY_OK:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        public_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
        public_obj.verify(signature, message) 
        # Si la verificación falla, debe lanzar una Excepción y el test fallará (rojo).

    elif keygen.PYNACL_OK:
        from nacl.signing import VerifyKey
        verify_key = VerifyKey(public_bytes)
        verify_key.verify(message, signature)
        # Si la verificación pasa, no lanza nada y el test sigue (verde).
        
    else:
        pytest.fail("No se encontró biblioteca de crypto (cryptography o pynacl) para verificar")

    # Si el código llega hasta aquí, significa que .verify() no lanzó excepciones, 
    # por lo que el test fue exitoso.
    assert True