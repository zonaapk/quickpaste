#!/bin/bash
set -e

pip install -r requirements.txt
python -c "from app import db; db.create_all()"