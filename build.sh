#!/usr/bin/env bash
# Exit on error
set -o errexit

# Modify this line to match your project's structure
pip install -r requirements.txt
python manage.py collectstatic --no-input
python manage.py migrate