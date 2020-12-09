import os
import requests

EMAIL_URL = os.environ.get('LAST_SEEN_ENDPOINT', 'http://localhost:5001/api/')


def update_last_seen(authorization):
    header = {'Authorization': authorization}
    requests.post(url=EMAIL_URL, headers=header)
