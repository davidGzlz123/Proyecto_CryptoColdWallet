from decimal import Decimal, InvalidOperation
import json
import unicodedata
from typing import Any


def _is_int_number(n: Any) -> bool:
    # Es importante porque verifica si el valor es un entero pero no un booleano
    return isinstance(n, int) and not isinstance(n, bool)


def _number_to_canonical(n: Any) -> str:
    #Convierte lo siguiente:
    #- Enteros: sin punto decimal ni signos innecesarios.
    # Flotantes: sin ceros finales
    # Cambiarian -0 y -0.0 a 0. Eso es normalizar
    
    try:
        # Si es entero, lo único que devuelve es el número directo.
        if _is_int_number(n):
            return str(n)
        # Usa Decimal(str(n)) para evitar errores.
        d = Decimal(str(n))
    except (InvalidOperation, ValueError, TypeError):
        # En caso de error, usa json.dumps como respaldo.
        return json.dumps(n, separators=(",", ":"))

    # Normaliza -0 a 0
    if d == 0:
        return "0"

    # Este método elimina exponentes y ceros después del punto.
    d = d.normalize()

    # Si sale un entero, se coloca en formato sin decimales.
    if d == d.to_integral():
        return format(d.quantize(Decimal(1)), 'f')

    # Intenta usar formato plano.
    try:
        s = format(d, 'f')
    except Exception:
        # Si falla usa notación científica.
        s = format(d, 'E').replace('E', 'e')

    # Quita ceros y puntos innecesarios.
    if '.' in s:
        s = s.rstrip('0').rstrip('.')
    return s


def _string_to_canonical(s: str) -> str:
    # Funciona para cambiar las cadenas Unicode a forma NFC para tengan los mismos bytes.
    s_norm = unicodedata.normalize('NFC', s)
    # Usa json.dumps para comillas y caracteres especiales.
    # ensure_ascii=False permite mantener los caracteres Unicode originales.
    return json.dumps(s_norm, ensure_ascii=False)


def _value_to_canonical(v: Any) -> str:
    # Convierte un valor como dict, list, string en su forma JSON.
    if v is None:
        return 'null'
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if _is_int_number(v) or isinstance(v, float) or isinstance(v, Decimal):
        # Números: usa la conversión definida.
        return _number_to_canonical(v)
    if isinstance(v, str):
        # Cadenas: normalización.
        return _string_to_canonical(v)
    if isinstance(v, list) or isinstance(v, tuple):
        # Arreglos: se recorren y se unen por comas.
        inner = ','.join(_value_to_canonical(x) for x in v)
        return '[' + inner + ']'
    if isinstance(v, dict):
        # Diccionarios: las claves se ordenan según su código Unicode.
        items = []
        for k in sorted(v.keys()):
            # Las claves deben ser cadenas, si no lo son se convierten.
            if not isinstance(k, str):
                key_text = _string_to_canonical(str(k))
            else:
                key_text = _string_to_canonical(k)
            val_text = _value_to_canonical(v[k])
            # Se agrega el par clave:valor sin espacios.
            items.append(f'{key_text}:{val_text}')
        return '{' + ','.join(items) + '}'

    # Para tipos poco comunes o no estándar, se intenta poner directamente a JSON.
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


def canonicalize(tx_json: Any) -> bytes:
    # Si se recibe en bytes, primero se decodifica a texto.
    if isinstance(tx_json, (bytes, bytearray)):
        tx_json = tx_json.decode('utf-8')
    # Si se recibe una cadena JSON, se convierte a algún objeto de Python.
    if isinstance(tx_json, str):
        tx_json = json.loads(tx_json)

    # Se obtiene la representación recursiva.
    canonical_text = _value_to_canonical(tx_json)
    # Se devuelve en bytes UTF-8.
    return canonical_text.encode('utf-8')
