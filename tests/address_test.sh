#!/bin/bash
# Script para ejecutar las pruebas de Address 


echo "Corriendo tests de Derivación de Dirección..."

# Especificamos la ruta exacta al archivo de test
pytest -v tests/address_test.py

echo "¡Tests de Dirección finalizados!"