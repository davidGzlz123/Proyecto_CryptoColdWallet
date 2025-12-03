import json
import os
import pytest
import sys

# Obtiene la ruta absoluta de la carpeta 'tests' (donde está este archivo)
current_dir = os.path.dirname(os.path.abspath(__file__))
# Sube un nivel para llegar a la raíz del proyecto ('Proyecto_CryptoColdWallet')
project_root = os.path.dirname(current_dir)
# Añade la raíz del proyecto al path de búsqueda de Python
sys.path.insert(0, project_root)

# Importamos el módulo a probar
import app.nonce_manager as nm


# --- FIXTURE PARA USAR DB TEMPORAL ---
@pytest.fixture(autouse=True)
def temp_nonce_db(tmp_path, monkeypatch):
# Antes de cada test redirigimos NONCE_DB_PATH a un archivo temporal. Así garantizamos aislamiento y no tocamos la DB real
    test_db = tmp_path / "nonce_db.json"
    monkeypatch.setattr(nm, "NONCE_DB_PATH", str(test_db))

    # Limpiamos cualquier DB previa
    if test_db.exists():
        test_db.unlink()

    yield  # ejecución del test

    # Limpieza al terminar
    if test_db.exists():
        test_db.unlink()



# 1. NONCE INICIAL = 0

def test_nonce_inicial_es_cero():
    nonce = nm.get_nonce("0xAAA")
    assert nonce == 0



# 2. INCREMENTOS CONSECUTIVOS

def test_incrementos_consecutivos():
    addr = "0xABC"

    assert nm.get_nonce(addr) == 0

    nm.increment_nonce(addr)
    assert nm.get_nonce(addr) == 1

    nm.increment_nonce(addr)
    assert nm.get_nonce(addr) == 2

    nm.increment_nonce(addr)
    assert nm.get_nonce(addr) == 3



# 3. PERSISTENCIA EN DISCO

def test_persistencia_en_disco(tmp_path, monkeypatch):
    addr = "0x999"

    # Redirigimos la DB a un archivo temporal propio del test
    test_db = tmp_path / "nonce_test.json"
    monkeypatch.setattr(nm, "NONCE_DB_PATH", str(test_db))

    # Incrementar y guardar
    nm.increment_nonce(addr)
    nm.increment_nonce(addr)

    # Comprobar que el archivo existe
    assert os.path.exists(test_db)

    # Leer el archivo manualmente
    with open(test_db, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data[addr] == 2



# 4. MANEJO DE ADDRESS DESCONOCIDAS

def test_address_desconocida_devuelve_cero():
    nonce = nm.get_nonce("0xNOEXISTO")
    assert nonce == 0



# 5. RECHAZO DE NONCE VIEJO

def test_replay_attack_nonce_viejo():
    addr = "0xREPLAY"

    # nonce esperado = 0 inicialmente
    nm.increment_nonce(addr)  # ahora esperado = 1

    # enviar tx con nonce viejo (0)
    with pytest.raises(ValueError) as e:
        nm.validate_nonce(addr, 0)

    assert "Posible Replay Attack" in str(e.value)



# 6. NONCE MAYOR AL ESPERADO (FUERA DE ORDEN)

def test_nonce_fuera_de_orden():
    addr = "0xORDER"

    nm.increment_nonce(addr)  # nonce esperado = 1

    # Enviar nonce muy grande
    with pytest.raises(ValueError) as e:
        nm.validate_nonce(addr, 5)

    assert "fuera de orden" in str(e.value)
