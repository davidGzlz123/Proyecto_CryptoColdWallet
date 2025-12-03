#!/bin/bash
# Script para ejecutar la Suite de Integración Completa

echo "🚀 Corriendo Tests de Integración (Ciclo de Vida + Ataques)..."
# Usamos -v (verbose) y -s (para ver los prints de los pasos)
pytest -v -s tests/test_integration.py

echo "Suite de Integración finalizada."