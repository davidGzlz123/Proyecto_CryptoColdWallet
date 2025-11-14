import os
import json
import tempfile
import pytest # La librería para hacer pruebas (necesitas `pip install pytest`)

# Importamos las funciones de nuestro script
# Asumimos que el script se llama 'keystore.py'
from keystore import (
    generate_ed25519_keypair,
    make_keystore,
    save_keystore,
    load_keystore,
    unlock_keystore,
    b64u,
)

# --- Fixtures de Pytest ---
# Las 'fixtures' son funciones que preparan datos para nuestras pruebas.
# Se ejecutan antes de cada prueba que las pida como argumento.

@pytest.fixture
def keypair():
# Esta fixture genera un par de llaves (privada, pública) una vez
    return generate_ed25519_keypair()

@pytest.fixture
def passphrase():
# Esta fixture solo provee una contraseña de prueba
    return "mi-pass-123"


# --- Pruebas  ---

# Genera llaves
# Crea un keystore
# Lo guarda en un archivo temporal
# Lo vuelve a cargar
# Lo desbloquea con la contraseña correcta
# Verifica que las llaves recuperadas sean idénticas a las originales
def test_unlock_ok(keypair, passphrase):
    # Obtenemos los datos de las fixtures
    priv_pem, pub_raw = keypair
    
    # Crear el keystore en memoria
    ks = make_keystore(priv_pem, pub_raw, passphrase)
    
    # Usar un directorio temporal para guardar el archivo
    # 'with' se asegura de que el directorio se borre al final
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "ks.json")
        # Guardar y cargar
        save_keystore(path, ks)
        loaded = load_keystore(path)
        # Desbloquear
        priv2, pub2 = unlock_keystore(loaded, passphrase)
        # Verificar (assert)
        # Si esto es falso, el test falla
        assert priv2 == priv_pem
        assert pub2 == pub_raw


# Crea un keystore
# Lo carga
# Intenta desbloquearlo con una contraseña INCORRECTA
# Verifica que el programa lance un error 'ValueError'
def test_unlock_bad_passphrase(keypair, passphrase):
    priv_pem, pub_raw = keypair
    ks = make_keystore(priv_pem, pub_raw, passphrase)
    # El test PASA si el código dentro del 'with' lanza un ValueError
    # El test FALLA si NO lanza un ValueError
    with pytest.raises(ValueError):
        print("   (Intentando desbloquear con clave incorrecta, esperamos que falle...)")
        unlock_keystore(ks, "incorrecta")
    print("   (Falló como se esperaba)")

# Crea un keystore
# Modifica el ciphertext
# Intenta desbloquearlo
# Verifica que la función `unlock_keystore` detecte la corrupción y lance un 'ValueError'.
def test_checksum_detection(keypair, passphrase):
    priv_pem, pub_raw = keypair
    ks = make_keystore(priv_pem, pub_raw, passphrase)
    # Creamos una copia para modificarla sin afectar 'ks'
    # La forma fácil es convertir a string JSON y de vuelta a diccionario
    ks_corrupt = json.loads(json.dumps(ks))
    # Corrompemos el ciphertext
    ks_corrupt["crypto"]["ciphertext"] = b64u(b"datos corruptos aqui")
    # Esperamos que 'unlock_keystore' falle por culpa del checksum
    with pytest.raises(ValueError) as e:
        unlock_keystore(ks_corrupt, passphrase)
    # Verificamos que el error sea por el checksum
    assert "Checksum inválido" in str(e.value)
    print("   (Corrupción detectada por checksum, OK)")

# Prueba que `load_keystore` falle si el JSON es inválido, 'tmp_path' es una fixture de pytest que da una ruta temporal
def test_load_invalid_format(tmp_path):
    # Creamos una ruta a un archivo
    bad = tmp_path / "bad.json"
    # Escribimos un JSON que no tiene nada que ver con nuestro formato
    bad.write_text("{\"campo_incorrecto\": 123}")
    # Esperamos que 'load_keystore' falle con ValueError
    with pytest.raises(ValueError):
        load_keystore(str(bad))

# Crea 5 keystores seguidos con contraseñas diferentes y verifica que todos se puedan desbloquear
def test_multiple_rounds():
    for i in range(5):
        priv, pub = generate_ed25519_keypair()
        passw = f"pass-{i}"
        ks = make_keystore(priv, pub, passw)
        priv2, pub2 = unlock_keystore(ks, passw)
        assert priv2 == priv
        assert pub2 == pub

# Usa contraseñas aleatorias (con letras y números) paraasegurar que no haya problemas con caracteres especiales
def test_stability_with_random_passphrases():
    import random
    import string
    for _ in range(3):
        priv, pub = generate_ed25519_keypair()
        # Genera una contraseña aleatoria de 12 caracteres
        passw = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        ks = make_keystore(priv, pub, passw)
        priv2, pub2 = unlock_keystore(ks, passw)
        assert priv2 == priv
        assert pub2 == pub

