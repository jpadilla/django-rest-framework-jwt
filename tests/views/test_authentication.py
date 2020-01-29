# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django.utils.encoding import force_text
from django.utils.translation import ugettext_lazy as _

from rest_framework import status

from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.compat import has_set_cookie_samesite
from rest_framework_jwt.settings import api_settings

def test_empty_credentials_returns_validation_error(call_auth_endpoint):
    expected_output = {
        "password": [_("This field may not be blank.")],
        "username": [_("This field may not be blank.")],
    }

    response = call_auth_endpoint("", "")

    assert response.json() == expected_output


def test_auth__invalid_credentials__returns_validation_error(
    call_auth_endpoint,
):
    expected_output = {
        "non_field_errors": [_("Unable to log in with provided credentials.")]
    }

    response = call_auth_endpoint("invalid_username", "invalid_password")

    assert response.json() == expected_output


def test_valid_credentials_return_jwt(user, call_auth_endpoint):
    response = call_auth_endpoint("username", "password")

    token = response.json()["token"]
    payload = JSONWebTokenAuthentication.jwt_decode_token(token)

    assert response.status_code == status.HTTP_200_OK
    assert payload["user_id"] == user.id
    assert payload["username"] == user.get_username()


def test_valid_credentials_with_aud_and_iss_settings_return_jwt(
    monkeypatch, user, call_auth_endpoint
):
    monkeypatch.setattr(api_settings, "JWT_AUDIENCE", "test-aud")
    monkeypatch.setattr(api_settings, "JWT_ISSUER", "test-iss")

    response = call_auth_endpoint("username", "password")

    token = response.json()["token"]
    payload = JSONWebTokenAuthentication.jwt_decode_token(token)

    assert response.status_code == status.HTTP_200_OK
    assert payload["aud"] == "test-aud"
    assert payload["iss"] == "test-iss"
    assert payload["user_id"] == user.id
    assert payload["username"] == user.get_username()


def test_valid_credentials_with_JWT_GET_USER_SECRET_KEY_set_return_jwt(
    monkeypatch, user, call_auth_endpoint
):
    def jwt_get_user_secret_key(user):
        return "{0}-{1}-{2}".format(user.pk, user.get_username(), "key")

    monkeypatch.setattr(
        api_settings, "JWT_GET_USER_SECRET_KEY", jwt_get_user_secret_key
    )

    response = call_auth_endpoint("username", "password")

    token = response.json()["token"]
    payload = JSONWebTokenAuthentication.jwt_decode_token(token)

    assert response.status_code == status.HTTP_200_OK
    assert payload["user_id"] == user.id
    assert payload["username"] == user.get_username()


def test_valid_credentials_with_no_user_id_setting_returns_jwt(
    monkeypatch, user, call_auth_endpoint
):
    monkeypatch.setattr(api_settings, "JWT_PAYLOAD_INCLUDE_USER_ID", False)

    response = call_auth_endpoint("username", "password")

    token = response.json()["token"]
    payload = JSONWebTokenAuthentication.jwt_decode_token(token)

    assert response.status_code == status.HTTP_200_OK
    assert "user_id" not in payload
    assert payload["username"] == user.get_username()


def test_valid_credentials_inactive_user_return_validation_error(
    create_user, call_auth_endpoint
):
    expected_output = {
        "non_field_errors": [_("Unable to log in with provided credentials.")]
    }

    create_user(username="inactive", password="password", is_active=False)

    response = call_auth_endpoint("inactive", "password")

    assert response.json() == expected_output


def test_valid_credentials_with_auth_cookie_enabled_returns_jwt_and_cookie(
    monkeypatch, user, call_auth_endpoint
):

    auth_cookie = "jwt-auth"
    monkeypatch.setattr(api_settings, "JWT_AUTH_COOKIE", auth_cookie)

    response = call_auth_endpoint("username", "password")

    assert auth_cookie in response.cookies

    setcookie = response.cookies[auth_cookie]

    assert 'domain' not in setcookie.items()
    assert setcookie['path'] == '/'
    assert setcookie['secure'] is True
    assert setcookie['httponly'] is True	# hardcoded
    if has_set_cookie_samesite():
        assert setcookie['samesite'] == 'Lax'

    assert response.status_code == status.HTTP_200_OK
    assert "token" in force_text(response.content)
    assert auth_cookie in response.client.cookies

def test_auth_cookie_settings(
    monkeypatch, user, call_auth_endpoint
):

    auth_cookie = "jwt-auth"
    monkeypatch.setattr(api_settings, "JWT_AUTH_COOKIE", auth_cookie)
    monkeypatch.setattr(api_settings, "JWT_AUTH_COOKIE_DOMAIN", '.do.main')
    monkeypatch.setattr(api_settings, "JWT_AUTH_COOKIE_PATH", '/pa/th')
    monkeypatch.setattr(api_settings, "JWT_AUTH_COOKIE_SECURE", False)
    monkeypatch.setattr(api_settings, "JWT_AUTH_COOKIE_SAMESITE", 'Strict')

    response = call_auth_endpoint("username", "password")

    assert auth_cookie in response.cookies

    setcookie = response.cookies[auth_cookie]

    assert setcookie['domain'] == '.do.main'
    assert setcookie['path'] == '/pa/th'
    assert 'secure' not in setcookie.items()
    assert setcookie['httponly'] is True	# hardcoded
    if has_set_cookie_samesite():
        assert setcookie['samesite'] == 'Strict'
