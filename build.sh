#!/usr/bin/env bash
# exit on error
set -o errexit

pip install -r requirements.txt

python manage.py collectstatic --no-input
echo python manage.py makemigrations --merge
python manage.py migrate
# echo "from django.contrib.auth     import get_user_model; User= get_user_model(); User.objects.create_superuser('Admin','Admin', 'pass123')"| python manage.py shell
