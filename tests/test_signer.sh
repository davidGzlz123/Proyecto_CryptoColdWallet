#!/bin/bash
# Script para ejecutar las pruebas del Signer 

echo "Corriendo tests del Signer..."

# Ejecutamos el test específico
pytest -v tests/test_signer.py

echo "¡Tests del Signer finalizados!"