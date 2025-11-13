#!/bin/bash
# Script para ejecutar las pruebas sobre el módulo dAEAD 

echo "Corriendo tests de AEAD..."

# Especificación de la ruta exacta al archivo de test
pytest -v tests/test_aead_gcm.py

echo "¡Tests de AEAD finalizados!"