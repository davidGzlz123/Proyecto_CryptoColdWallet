import os
import tempfile

import pytest

from app.keystore import (
    generate_ed25519_keypair,
    make_keystore,
    save_keystore,
    load_keystore,
    unlock_keystore,
    change_keystore_passphrase,
)


def _create_temp_keystore(path, passphrase="old-passphrase"):
    """
    Crea un keystore de prueba en 'path' usando la passphrase dada.
    Devuelve también (priv_pem, pub_raw) para poder comparar luego.
    """
    priv_pem, pub_raw = generate_ed25519_keypair()
    ks = make_keystore(priv_pem, pub_raw, passphrase)
    save_keystore(path, ks)
    return priv_pem, pub_raw


def test_change_passphrase_ok():
    """
    Caso exitoso:
    - Creamos un keystore con passphrase 'old-passphrase'.
    - Verificamos que se puede desbloquear con la pass antigua.
    - Cambiamos la pass a 'new-passphrase-123'.
    - Verificamos que:
        * Ya no funciona la pass antigua.
        * Sí funciona la pass nueva.
        * La llave privada y pública siguen siendo las mismas.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        ks_path = os.path.join(tmpdir, "keystore.json")

        # 1) Crear keystore inicial
        priv_orig, pub_orig = _create_temp_keystore(ks_path, passphrase="old-passphrase")

        # 2) Confirmar que la passphrase vieja funciona
        ks_loaded = load_keystore(ks_path)
        priv1, pub1 = unlock_keystore(ks_loaded, "old-passphrase")

        assert priv1 == priv_orig
        assert pub1 == pub_orig

        # 3) Cambiar la passphrase
        change_keystore_passphrase(ks_path, "old-passphrase", "new-passphrase-123")

        # 4) Cargar de nuevo el keystore modificado
        ks_after = load_keystore(ks_path)

        # 5) La passphrase vieja debe fallar
        with pytest.raises(ValueError):
            unlock_keystore(ks_after, "old-passphrase")

        # 6) La nueva passphrase debe funcionar y devolver las mismas llaves
        priv2, pub2 = unlock_keystore(ks_after, "new-passphrase-123")

        assert priv2 == priv_orig
        assert pub2 == pub_orig


def test_change_passphrase_wrong_old():
    """
    Si la passphrase antigua es incorrecta, change_keystore_passphrase
    debe lanzar ValueError y NO modificar el archivo.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        ks_path = os.path.join(tmpdir, "keystore.json")

        # Crear keystore con pass correcta
        priv_orig, pub_orig = _create_temp_keystore(ks_path, passphrase="old-passphrase")

        # Intentar cambiar con pass antigua incorrecta
        with pytest.raises(ValueError):
            change_keystore_passphrase(ks_path, "pass-incorrecta", "new-passphrase-123")

        # Aún debe poderse desbloquear con la pass original
        ks_loaded = load_keystore(ks_path)
        priv1, pub1 = unlock_keystore(ks_loaded, "old-passphrase")

        assert priv1 == priv_orig
        assert pub1 == pub_orig


def test_change_passphrase_too_short():
    """
    Si la nueva passphrase es demasiado corta, la función debe rechazarla
    antes de tocar el keystore.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        ks_path = os.path.join(tmpdir, "keystore.json")

        # Crear keystore con pass correcta
        priv_orig, pub_orig = _create_temp_keystore(ks_path, passphrase="old-passphrase")

        # Intentar usar una nueva passphrase muy corta
        with pytest.raises(ValueError):
            change_keystore_passphrase(ks_path, "old-passphrase", "123")

        # El keystore debe seguir funcionando con la pass original
        ks_loaded = load_keystore(ks_path)
        priv1, pub1 = unlock_keystore(ks_loaded, "old-passphrase")

        assert priv1 == priv_orig
        assert pub1 == pub_orig
