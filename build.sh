#!/bin/bash
# Salir si un comando falla
set -o errexit

# Instalar las dependencias
pip install -r requirements.txt

# Crear la base de datos (si no existe)
python -c "from app import db; db.create_all()"