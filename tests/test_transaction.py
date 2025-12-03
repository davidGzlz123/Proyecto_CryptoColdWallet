# Pruebas unitarias para el módulo de transacciones.

# Aquí verificamos:
#  - La construcción correcta de transacciones con make_tx.
#  - La generación determinista de bytes canónicos con tx_canonical_bytes.
#  - El manejo de errores cuando faltan campos o los valores son inválidos.

import os
import sys
import pytest

# Ajuste de sys.path para poder importar el paquete 'app' desde la raíz del proyecto
current_dir = os.path.dirname(os.path.abspath(__file__))   # Carpeta 'tests'
project_root = os.path.dirname(current_dir)                # Carpeta raíz del proyecto
sys.path.insert(0, project_root)                           # Añadimos la raíz al path de Python

from app.transaction import make_tx, tx_canonical_bytes


def test_make_tx_basic():
    """
    Test básico de construcción de transacción.
    Verifica que make_tx cree un diccionario con los campos mínimos:
    'from', 'to', 'value' y 'nonce', y que el campo 'data' no aparezca
    si no se especifica.
    """
    tx = make_tx("0xAAA", "0xBBB", 10, 1)

    # Verificamos que los campos obligatorios estén presentes y correctos
    assert tx["from"] == "0xAAA"
    assert tx["to"] == "0xBBB"
    assert tx["value"] == 10
    assert tx["nonce"] == 1

    # 'data' no debería existir si no se proporcionó
    assert "data" not in tx


def test_make_tx_with_data():
    """
    Verifica que el campo opcional 'data' se incluya correctamente
    cuando se pasa como argumento.
    """
    tx = make_tx("0xAAA", "0xBBB", 10, 1, data="payload")

    # Debe existir el campo 'data' y contener el valor esperado
    assert tx["data"] == "payload"


def test_make_tx_invalid_value():
    """
    Verifica que make_tx rechace valores negativos en 'value'.
    En este caso, se espera que se lance un ValueError.
    """
    with pytest.raises(ValueError):
        make_tx("0xAAA", "0xBBB", -1, 1)


def test_make_tx_invalid_nonce():
    """
    Verifica que make_tx rechace valores negativos en 'nonce'.
    También se espera un ValueError.
    """
    with pytest.raises(ValueError):
        make_tx("0xAAA", "0xBBB", 10, -5)


def test_tx_canonical_bytes_deterministic():
    """
    Verifica que tx_canonical_bytes sea determinista:
    dos transacciones con el mismo contenido deben producir exactamente
    los mismos bytes canónicos.
    """
    tx1 = make_tx("0xAAA", "0xBBB", 10, 1)
    tx2 = make_tx("0xAAA", "0xBBB", 10, 1)

    b1 = tx_canonical_bytes(tx1)
    b2 = tx_canonical_bytes(tx2)

    # Ambos resultados deben ser idénticos
    assert b1 == b2
    # Y deben ser de tipo bytes (listos para firmarse)
    assert isinstance(b1, bytes)


def test_tx_canonical_bytes_independent_of_key_order():
    """
    Verifica que el orden de las claves en el diccionario no afecte
    los bytes canónicos finales.

    tx1 se crea con make_tx (orden "from", "to", "value", "nonce"),
    mientras que tx2 define las claves en un orden distinto.
    Gracias al canonicalizer interno, los bytes resultantes deben coincidir.
    """
    tx1 = make_tx("0xAAA", "0xBBB", 10, 1)
    tx2 = {
        "to": "0xBBB",
        "value": 10,
        "nonce": 1,
        "from": "0xAAA",
    }

    b1 = tx_canonical_bytes(tx1)
    b2 = tx_canonical_bytes(tx2)

    # Deben ser iguales a pesar del distinto orden de las claves
    assert b1 == b2


def test_tx_canonical_bytes_changes_if_field_changes():
    """
    Verifica que cualquier cambio significativo en la transacción
    (por ejemplo, en el campo 'value') produzca bytes canónicos distintos.
    Esto es importante para que una firma sea única para un contenido concreto.
    """
    tx1 = make_tx("0xAAA", "0xBBB", 10, 1)
    tx2 = make_tx("0xAAA", "0xBBB", 11, 1)  # Cambiamos 'value'

    b1 = tx_canonical_bytes(tx1)
    b2 = tx_canonical_bytes(tx2)

    # Los bytes canónicos deben ser diferentes
    assert b1 != b2


def test_tx_canonical_bytes_missing_field():
    """
    Verifica que tx_canonical_bytes falle si falta algún campo obligatorio.
    En este ejemplo falta el campo 'nonce' en la transacción.
    """
    tx_incompleta = {
        "from": "0xAAA",
        "to": "0xBBB",
        "value": 10,
        # "nonce" no está presente
    }

    # Se espera un ValueError indicando que falta un campo requerido
    with pytest.raises(ValueError):
        tx_canonical_bytes(tx_incompleta)
