#!/usr/bin/env bash
set -o errexit

echo "Starting build process..."
pip install -r requirements.txt
echo "Skipping collectstatic to avoid source map errors"
python manage.py migrate
echo "Build completed successfully!"