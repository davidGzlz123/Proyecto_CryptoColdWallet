#!/bin/bash
#
# Script para instalar las dependencias del proyecto
# Realiza la lectura el archivo requirements.txt

echo "Instalando dependencias de Python..."

# Usamos pip para instalar desde el archivo de requerimientos
pip install -r ../docs/requerimientos.txt

echo "¡Instalación completa! :)"