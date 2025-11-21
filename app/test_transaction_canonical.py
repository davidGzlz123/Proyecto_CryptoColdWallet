import os
import sys
import pytest

# Ajuste de sys.path para poder importar el paquete 'app' desde la raíz del proyecto
current_dir = os.path.dirname(os.path.abspath(__file__))   # Carpeta 'tests'
project_root = os.path.dirname(current_dir)                # Carpeta raíz del proyecto
sys.path.insert(0, project_root)                           # Añadimos la raíz al path de Python


from app.transaction import make_tx, tx_canonical_bytes
from app.canonicalizer import canonicalize

# Tests para make_tx()
# Confirma que make_tx cree correctamente una transacción completa con todos los campos, incluyendo data
def test_make_valid_tx():
    tx = make_tx("Alice", "Bob", 100, 1, "datos opcionales")
    assert tx == {
        "from": "Alice",
        "to": "Bob",
        "value": 100,
        "nonce": 1,
        "data": "datos opcionales"
    }

# Verifica que make_tx cree correctamente una transacción cuando no se proporciona data
def test_make_tx_validatest_make_tx_without_data():
    tx = make_tx("Alice", "Bob", 50, 0)
    assert tx == {
        "from": "Alice",
        "to": "Bob",
        "value": 50,
        "nonce": 0
    }

# Verifica que make_tx lance ValueError si los tipos de entrada son incorrectos o si los valores numéricos son negativos
def test_make_tx_incorrect_types():
    with pytest.raises(ValueError):
        make_tx(123, "Bob", 50, 0)
    with pytest.raises(ValueError):
        make_tx("Alice", 456, 50, 0)
    with pytest.raises(ValueError):
        make_tx("Alice", "Bob", -10, 0)
    with pytest.raises(ValueError):
        make_tx("Alice", "Bob", 50, -1)
    with pytest.raises(ValueError):
        make_tx("Alice", "Bob", 50, 0, data=123)


# Tests para tx_canonical_bytes()
# Verifica que tx_canonical_bytes devuelva bytes y que la salida coincida con la función canonicalize
def test_tx_canonical_bytes_valid():
    tx = make_tx("Alice", "Bob", 100, 1, "datos")
    result = tx_canonical_bytes(tx)
    assert isinstance(result, bytes)
    # También podemos comparar con canonicalize directamente
    assert result == canonicalize(tx)

# Verifica que los números se normalicen correctamente incluyendo cero y enteros
def test_tx_canonical_bytes_numeric_values():
    tx = make_tx("Alice", "Bob", 100, 0)
    canon = tx_canonical_bytes(tx)
    # Asegura que los números se normalicen correctamente
    canon_str = canon.decode('utf-8')
    assert '"value":100' in canon_str
    assert '"nonce":0' in canon_str

# Verifica que strings con caracteres Unicode se normalicen correctamente y se mantengan en JSON
def test_tx_canonical_bytes_unicode():
    tx = make_tx("Álice", "Bób", 1, 1, "mensaje ñ")
    canon = tx_canonical_bytes(tx)
    canon_str = canon.decode('utf-8')
    # Las cadenas deben estar en JSON, Unicode preservado
    assert '"Álice"' in canon_str
    assert '"Bób"' in canon_str
    assert '"mensaje ñ"' in canon_str

# Verifica que se lance ValueError si falta algún campo obligatorio como to, from, value o nonce
def test_tx_canonical_bytes_missing():
    tx_incompleta = {"from": "Alice", "value": 10, "nonce": 0}
    with pytest.raises(ValueError) as excinfo:
        tx_canonical_bytes(tx_incompleta)
    assert "Falta el campo obligatorio 'to'" in str(excinfo.value)

# Verifica que tx_canonical_bytes lance ValueError si el argumento no es un diccionario
def test_tx_canonical_bytes_incorrect_type():
    with pytest.raises(ValueError):
        tx_canonical_bytes("no es un dict")

# Verifica que listas y diccionarios se canonizan correctamente
def test_tx_canonical_bytes_list_and_dict():
    tx = make_tx("Alice", "Bob", 42, 7, "mensaje")
    tx["extra"] = [3, 1, 0, {"k": -0.0}]
    canon = tx_canonical_bytes(tx)
    canon_str = canon.decode('utf-8')
    # Verifica que listas y diccionarios se canonizan correctamente
    assert canon_str.endswith('{"k":0}]}')  # -0.0 se normaliza a 0

# Verifica una transacción completa con campos adicionales y la normalización de números decimales
def test_complete_transaction_and_fee():
    tx = make_tx("Alice", "Bob", 42, 7, "mensaje")
    tx["meta"] = {"nested": [0, 1.0, 2.5000]}
    canon_bytes = tx_canonical_bytes(tx)
    canon_str = canon_bytes.decode('utf-8')
    # Deben normalizarse los números: 1.0 -> 1, 2.5000 -> 2.5
    assert "1" in canon_str
    assert "2.5" in canon_str
