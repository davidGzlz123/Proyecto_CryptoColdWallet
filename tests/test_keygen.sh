#!/bin/bash
# Script para ejecutar las pruebas de integridad del test_keygen.py para llaves de Ed25519.

echo "Corriendo tests de integridad para key_gen.py..."

# Ejecuta pytest en modo verbose (-v) para ver cada test.
# Pytest encontrará automáticamente el archivo test_keygen.py
pytest -v

echo "¡Tests finalizados!"