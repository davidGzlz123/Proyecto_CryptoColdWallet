#!/bin/bash
# Script para ejecutar las pruebas de Keystore usando pytest

echo "Corriendo tests de Keystore..."

# Especificamos la ruta exacta al archivo de test
pytest -v tests/keystore_test.py

echo "¡Tests de Keystore finalizados!"