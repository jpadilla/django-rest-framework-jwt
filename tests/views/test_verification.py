# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.compat import gettext_lazy as _
from rest_framework_jwt.settings import api_settings


def test_invalid_token_returns_validation_error(call_auth_verify_endpoint):
    expected_output = {"non_field_errors": [_("Error decoding token.")]}

    response = call_auth_verify_endpoint("invalid_token")

    assert response.json() == expected_output


def test_valid_token_returns_same_token(
    user, call_auth_endpoint, call_auth_verify_endpoint
):
    auth_response = call_auth_endpoint("username", "password")
    auth_token = auth_response.json()["token"]

    verify_response = call_auth_verify_endpoint(auth_token)
    verify_token = verify_response.json()["token"]

    assert verify_token == auth_token


def test_token_without_username_returns_validation_error(
    user, call_auth_verify_endpoint
):
    payload = JSONWebTokenAuthentication.jwt_create_payload(user)
    payload.pop("username")
    auth_token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

    expected_output = {"non_field_errors": [_("Invalid token.")]}

    verify_response = call_auth_verify_endpoint(auth_token)

    assert verify_response.json() == expected_output


def test_token_with_invalid_username_returns_validation_error(
    user, call_auth_verify_endpoint
):
    payload = JSONWebTokenAuthentication.jwt_create_payload(user)
    payload["username"] = "i_do_not_exist"
    auth_token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

    expected_output = {"non_field_errors": [_("User doesn't exist.")]}

    verify_response = call_auth_verify_endpoint(auth_token)
    assert verify_response.json() == expected_output


def test_token_for_inactive_user_returns_validation_error(
    create_user, call_auth_verify_endpoint
):
    inactive_user = create_user(
        username="inactive", password="password", is_active=False
    )
    payload = JSONWebTokenAuthentication.jwt_create_payload(inactive_user)
    auth_token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

    expected_output = {"non_field_errors": [_("User account is disabled.")]}

    verify_response = call_auth_verify_endpoint(auth_token)
    assert verify_response.json() == expected_output


def test_expired_token_returns_validation_error(
    user, call_auth_verify_endpoint
):
    payload = JSONWebTokenAuthentication.jwt_create_payload(user)
    payload["iat"] = 0  # beginning of time
    payload["exp"] = 1  # one second after beginning of time
    auth_token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

    expected_output = {"non_field_errors": [_("Token has expired.")]}

    verify_response = call_auth_verify_endpoint(auth_token)
    assert verify_response.json() == expected_output

def test_invalid_username_with_JWT_GET_USER_SECRET_KEY_returns_validation_error(
    monkeypatch, user, call_auth_verify_endpoint
):
    def jwt_get_user_secret_key(user):
        return "{0}-{1}-{2}".format(user.pk, user.get_username(), "key")

    payload = JSONWebTokenAuthentication.jwt_create_payload(user)
    payload["username"] = "i_do_not_exist"
    auth_token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

    monkeypatch.setattr(
        api_settings, "JWT_GET_USER_SECRET_KEY", jwt_get_user_secret_key
    )

    expected_output = {"non_field_errors": [_("User doesn't exist.")]}

    verify_response = call_auth_verify_endpoint(auth_token)
    assert verify_response.json() == expected_output
