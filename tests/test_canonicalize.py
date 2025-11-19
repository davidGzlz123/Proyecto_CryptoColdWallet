from canonicalizer import canonicalize


def test_simple_object():
    # Las claves deben aparecer en orden.
    obj = {"b": 2, "a": 1}
    out = canonicalize(obj).decode('utf-8')
    assert out == '{"a":1,"b":2}'


def test_nested_object_and_array():
    # Se prueban estructuras anidadas y arreglos.
    obj = {"z": [3, {"b": 2, "a": [1, 2]}], "a": None}
    out = canonicalize(obj).decode('utf-8')
    assert out == '{"a":null,"z":[3,{"a":[1,2],"b":2}]}'


def test_strings_unicode_normalization():
    # Verifica que 'e' + acento sea igual a 'é' colocado desde el principio.
    a = {'s': 'e\u0301'}
    b = {'s': '\u00e9'}
    out_a = canonicalize(a).decode('utf-8')
    out_b = canonicalize(b).decode('utf-8')
    assert out_a == out_b


def test_numbers_integer_and_float():
    # Verifica eliminación de ceros y notación científica.
    obj = {"int": 10, "float": 1.2300, "small": 0.00001, "big": 1e6}
    out = canonicalize(obj).decode('utf-8')
    assert out == '{"big":1000000,"float":1.23,"int":10,"small":0.00001}'


def test_negative_zero_normalized():
    # -0.0 debe ser normalizado a 0.
    obj = {"n": -0.0}
    out = canonicalize(obj).decode('utf-8')
    assert out == '{"n":0}'


def test_boolean_and_null():
    # true/false/null deben ir en minúsculas y ordenadas.
    obj = {"t": True, "f": False, "n": None}
    out = canonicalize(obj).decode('utf-8')
    assert out == '{"f":false,"n":null,"t":true}'


if __name__ == '__main__':
    examples = [
        ('Original JSON string', '{"b":2, "a":1}'),
        ('Nested example', '{"z":[3,{"b":2,"a":[1,2]}], "a":null}'),
        ('Numbers', '{"int":10, "float":1.2300, "small":0.00001, "big":1e6}'),
        ('Unicode', '{"s":"e\\u0301"}'),
        ('Negative zero', '{"n":-0.0}'),
    ]

    for title, j in examples:
        print('---', title, '---')
        print('Before:', j)
        can = canonicalize(j)
        print('After :', can.decode('utf-8'))
        print()
