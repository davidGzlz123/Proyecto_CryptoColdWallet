# tests/test_aead_gcm.py
# Tests desarrollados para el módulo AEAD.

import sys
import os
# Obtiene la ruta absoluta de la carpeta 'tests' (donde está este archivo)
current_dir = os.path.dirname(os.path.abspath(__file__))
# Sube un nivel para llegar a la raíz del proyecto ('Proyecto_CryptoColdWallet')
project_root = os.path.dirname(current_dir)
# Añade la raíz del proyecto al path de búsqueda de Python
sys.path.insert(0, project_root)

import pytest
from app import aead_gcm 
from app.aead_gcm import EncryptedData 


# Tests de helpers de Base64 y serialización
def test_b64_helpers_roundtrip():
    """Test 1: Verificación de los helpers de Base64"""
    original_bytes = b"datos \x01\x02 con bytes raros \xFF"
    b64_string = aead_gcm.bytes_to_b64(original_bytes)
    assert isinstance(b64_string, str)
    restored_bytes = aead_gcm.b64_to_bytes(b64_string)
    assert restored_bytes == original_bytes

def test_dict_serialization_roundtrip():
    """Test 2: Verificación de la serialización a dict y viceversa"""
    ed = EncryptedData(
        ciphertext=b"datos_cifrados_abc",
        nonce=b"nonce_123",
        tag=b"tag_xyz"
    )
    
    data_dict = ed.to_dict()
    
    # Verificación de que las claves existan y sean strings b-64
    assert data_dict["ciphertext_b64"] == "ZGF0b3NfY2lmcmFkb3NfYWJj"
    assert data_dict["nonce_b64"] == "bm9uY2VfMTIz"
    assert data_dict["tag_b64"] == "dGFnX3h5eg=="
    
    # Verificación del camino inverso (deserialización)
    restored_ed = EncryptedData.from_dict(data_dict)
    assert restored_ed.ciphertext == b"datos_cifrados_abc"
    assert restored_ed.nonce == b"nonce_123"
    assert restored_ed.tag == b"tag_xyz"

# Tests de cifrado y descifrado AEAD AES-256-GCM
def test_encrypt_decrypt_roundtrip():
    """Test 3: Cifrado y descifrado."""
    
    # 1. Generación de una llave aleatoria para el test
    key = os.urandom(aead_gcm.AES_KEY_SIZE) # 32 bytes de tamaño
    plaintext = b"Este es el mensaje ultra secreto de P1!"
    
    # 2. Cifrado del plaintext
    encrypted_payload = aead_gcm.encrypt(key, plaintext)
    
    # 3. Verificación del payload cifrado
    assert isinstance(encrypted_payload, EncryptedData)
    assert len(encrypted_payload.nonce) == aead_gcm.GCM_NONCE_SIZE
    assert len(encrypted_payload.tag) == aead_gcm.GCM_TAG_SIZE

    # Se asegura que el ciphertext es diferente al plaintext
    assert encrypted_payload.ciphertext != plaintext
    
    # 4. Descifrado del payload
    decrypted_plaintext = aead_gcm.decrypt(key, encrypted_payload)
    
    # 5. Verificación final del plaintext descifrado
    assert decrypted_plaintext == plaintext

# Test para verificar el fallo del módulo con una llave incorrecta
def test_decrypt_fails_with_wrong_key():
    """Test 4: Verificación del fallo si la llave empleada es incorrecta."""
    key1 = os.urandom(aead_gcm.AES_KEY_SIZE) # Llave correcta
    key2 = os.urandom(aead_gcm.AES_KEY_SIZE) # Llave incorrecta
    plaintext = b"mensaje"
    
    encrypted_payload = aead_gcm.encrypt(key1, plaintext)
    
    # Intenta descifrar con la key2 (incorrecta)
    # Uso de pytest.raises para "esperar" que la función falle
    with pytest.raises(ValueError, match="Error de autenticacion"):
        aead_gcm.decrypt(key2, encrypted_payload)