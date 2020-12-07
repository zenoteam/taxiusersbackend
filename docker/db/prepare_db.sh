#!/bin/sh
set -e

/opt/code/db/start_postgres.sh

echo 'Creating Schema'
cd /opt/code/

flask db upgrade

echo 'Loading initial data'
python3 /opt/code/load_test_data.py

/opt/code/db/stop_postgres.sh
