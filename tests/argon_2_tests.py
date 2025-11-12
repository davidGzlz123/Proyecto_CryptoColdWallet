import pytest
from argon_2_wrapper import create_random_salt, generate_key_from_passphrase, Argon2Settings

#   Verifica que la función create_random_salt devuelve un salt con el tamaño especificado
def test_create_random_salt_length():

    salt = create_random_salt(12)
    assert isinstance(salt, bytes)
    assert len(salt) == 12

#   Verifica que los salts generados por create_random_salt sean únicos. 
#   Asi se garantiza que cada clave generada sea diferente incluso si la misma contraseña es usada
def test_create_random_salt_uniqueness():
    salt_a = create_random_salt()
    salt_b = create_random_salt()
    assert salt_a != salt_b

#   Verifica que la función devuelve la misma clave cuando se le pasa la misma contraseña y el mismo salt
def test_generate_key_same_input_same_output():
    password = "my_secret_password"
    salt = create_random_salt()
    key1 = generate_key_from_passphrase(password, salt)
    key2 = generate_key_from_passphrase(password, salt)
    assert key1 == key2


#   Verifica que la función devuelve claves diferentes cuando se le pasa la misma contraseña pero diferentes salts
def test_generate_key_different_salt_different_key():
    password = "my_secret_password"
    salt1 = create_random_salt()
    salt2 = create_random_salt()
    key1 = generate_key_from_passphrase(password, salt1)
    key2 = generate_key_from_passphrase(password, salt2)
    assert key1 != key2

#    Verifica que la función devuelva una clave segura cuando se le pasa una contraseña, un salt y configuración personalizada
def test_generate_key_with_custom_settings():
    
    password = b"another_password"
    salt = create_random_salt(20)
    settings = Argon2Settings(time_cost=1, memory_cost=8 * 1024, parallelism=1, key_size=16)
    key = generate_key_from_passphrase(password, salt, settings=settings)
    assert isinstance(key, bytes)
    assert len(key) == 16

#    Verifica que la función devuelva una clave generada es tipo bytes y tiene el tamaño especificado.
def test_invalid_salt_type():
    with pytest.raises(TypeError):
        generate_key_from_passphrase("pw", salt="not-bytes")

#    Verifica que la función lanza un ValueError cuando se le pasa un salt que tiene menos de 8 bytes.
def test_short_salt_rejected():
    with pytest.raises(ValueError):
        generate_key_from_passphrase("pw", salt=b"tiny")

#   Verifica que la función lanza un TypeError cuando se le pasa una contraseña que no es de tipo str o bytes.
def test_invalid_passphrase_type():
    with pytest.raises(TypeError):
        generate_key_from_passphrase(1234, salt=create_random_salt())

if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
