"""
Test the User operations
"""
from unittest.mock import ANY, patch
import http.client
from freezegun import freeze_time

from faker import Faker
fake = Faker()


@freeze_time('2019-05-07 13:47:34')
def test_create_user(client):
    new_user = {
        'username': fake.name(),
        'password': fake.password(length=15, special_chars=True),
        'role': 1,
    }
    response = client.post('/admin/users/', data=new_user)
    result = response.json

    assert http.client.CREATED == response.status_code

    expected = {
        'id': ANY,
        'username': new_user['username'],
        'role': new_user['role'],
        'lastLoginAt': ANY,
        'createdAt': '2019-05-07T13:47:34',
    }
    assert result == expected


def test_login(client):
    USERNAME = fake.name()
    PASSWORD = fake.password(length=15, special_chars=True)
    new_user = {
        'username': USERNAME,
        'password': PASSWORD,
        'role': 1,
    }
    response = client.post('/admin/users/', data=new_user)
    assert http.client.CREATED == response.status_code

    response = client.post('/api/login/', data=new_user)
    result = response.json
    assert http.client.OK == response.status_code

    expected = {
        'Authorized': ANY,
    }
    assert result == expected


def test_verify(client):
    USERNAME = fake.name()
    PASSWORD = fake.password(length=15, special_chars=True)
    new_user = {
        'username': USERNAME,
        'password': PASSWORD,
        'role': 1,
    }
    response = client.post('/admin/users/', data=new_user)
    assert http.client.CREATED == response.status_code

    response = client.post('/api/login/', data=new_user)
    result = response.json
    assert http.client.OK == response.status_code

    expected = {
        'Authorized': ANY,
    }
    assert result == expected
    headers = {'Authorization': result['Authorized']}
    response = client.get('/api/verify/', headers=headers)
    assert http.client.OK == response.status_code


def test_logout(client):
    USERNAME = fake.name()
    PASSWORD = fake.password(length=15, special_chars=True)
    new_user = {
        'username': USERNAME,
        'password': PASSWORD,
        'role': 1,
    }
    response = client.post('/admin/users/', data=new_user)
    assert http.client.CREATED == response.status_code

    response = client.post('/api/login/', data=new_user)
    result = response.json
    assert http.client.OK == response.status_code

    expected = {
        'Authorized': ANY,
    }
    assert result == expected
    headers = {'Authorization': result['Authorized']}
    response = client.post('/api/logout/', headers=headers)
    assert http.client.OK == response.status_code


def test_wrong_password(client):
    USERNAME = fake.name()
    PASSWORD = fake.password(length=15, special_chars=True)
    new_user = {
        'username': USERNAME,
        'password': PASSWORD,
        'role': 1,
    }
    response = client.post('/admin/users/', data=new_user)
    assert http.client.CREATED == response.status_code

    fake_user = {
        'username': new_user['username'],
        'password': fake.password(length=15, special_chars=True),
    }
    response = client.post('/api/login/', data=fake_user)
    assert http.client.UNAUTHORIZED == response.status_code


def test_update_password(client):
    USERNAME = fake.name()
    PASSWORD = fake.password(length=15, special_chars=True)
    new_user = {
        'username': USERNAME,
        'password': PASSWORD,
        'role': 1,
    }
    response = client.post('/admin/users/', data=new_user)
    new_user_result = response.json
    assert http.client.CREATED == response.status_code

    response = client.post('/api/login/', data=new_user)
    result = response.json
    assert http.client.OK == response.status_code

    expected = {
        'Authorized': ANY,
    }
    assert result == expected

    new_pw = {
        'userId': new_user_result['id'],
        'new_password': fake.password(length=15, special_chars=True),
    }
    headers = {'Authorization': result['Authorized']}
    response = client.post('/api/password/update/', data=new_pw, headers=headers)
    assert http.client.OK == response.status_code


def test_update_password_login(client):
    USERNAME = fake.name()
    PASSWORD = fake.password(length=15, special_chars=True)
    new_user = {
        'username': USERNAME,
        'password': PASSWORD,
        'role': 1,
    }
    response = client.post('/admin/users/', data=new_user)
    new_user_result = response.json
    assert http.client.CREATED == response.status_code

    response = client.post('/api/login/', data=new_user)
    result = response.json
    assert http.client.OK == response.status_code

    expected = {
        'Authorized': ANY,
    }
    assert result == expected

    new_pw = {
        'userId': new_user_result['id'],
        'new_password': fake.password(length=15, special_chars=True),
    }
    headers = {'Authorization': result['Authorized']}
    response = client.post('/api/password/update/', data=new_pw, headers=headers)
    assert http.client.OK == response.status_code

    user = {
        'username': USERNAME,
        'password': new_pw['new_password'],
    }

    response = client.post('/api/login/', data=user)
    result = response.json
    assert http.client.OK == response.status_code

    expected = {
        'Authorized': ANY,
    }
    assert result == expected


def test_change_password(client):
    USERNAME = fake.name()
    PASSWORD = fake.password(length=15, special_chars=True)
    new_user = {
        'username': USERNAME,
        'password': PASSWORD,
        'role': 1,
    }
    response = client.post('/admin/users/', data=new_user)
    assert http.client.CREATED == response.status_code

    response = client.post('/api/login/', data=new_user)
    result = response.json
    assert http.client.OK == response.status_code

    expected = {
        'Authorized': ANY,
    }
    assert result == expected

    new_pw = {
        'old_password': PASSWORD,
        'new_password': fake.password(length=15, special_chars=True),
    }
    headers = {'Authorization': result['Authorized']}
    response = client.post('/api/password/change/', data=new_pw, headers=headers)
    assert http.client.OK == response.status_code


def test_change_password_login(client):
    USERNAME = fake.name()
    PASSWORD = fake.password(length=15, special_chars=True)
    new_user = {
        'username': USERNAME,
        'password': PASSWORD,
        'role': 1,
    }
    response = client.post('/admin/users/', data=new_user)
    assert http.client.CREATED == response.status_code

    response = client.post('/api/login/', data=new_user)
    result = response.json
    assert http.client.OK == response.status_code

    expected = {
        'Authorized': ANY,
    }
    assert result == expected

    new_pw = {
        'old_password': PASSWORD,
        'new_password': fake.password(length=15, special_chars=True),
    }
    headers = {'Authorization': result['Authorized']}
    response = client.post('/api/password/change/', data=new_pw, headers=headers)
    assert http.client.OK == response.status_code

    user = {
        'username': USERNAME,
        'password': new_pw['new_password'],
    }

    response = client.post('/api/login/', data=user)
    result = response.json
    assert http.client.OK == response.status_code

    expected = {
        'Authorized': ANY,
    }
    assert result == expected
