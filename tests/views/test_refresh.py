# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from datetime import timedelta

from django.utils import timezone

from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.blacklist.models import BlacklistedToken
from rest_framework_jwt.compat import gettext_lazy as _
from rest_framework_jwt.settings import api_settings


def test_invalid_token__returns_validation_error(call_auth_refresh_endpoint):
    expected_output = {"non_field_errors": [_("Error decoding token.")]}

    response = call_auth_refresh_endpoint("invalid_token")
    assert response.json() == expected_output


def test_with_JWT_ALLOW_REFRESH_disabled__returns_validation_error(
    monkeypatch, call_auth_refresh_endpoint, user
):
    monkeypatch.setattr(api_settings, "JWT_ALLOW_REFRESH", False)

    payload = JSONWebTokenAuthentication.jwt_create_payload(user)
    payload["exp"] = payload["iat"] + 100  # add 100 seconds to issued at time
    auth_token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

    expected_output = {
        "non_field_errors": ["orig_iat field not found in token."]
    }

    refresh_response = call_auth_refresh_endpoint(auth_token)

    assert refresh_response.json() == expected_output


def test_without_orig_iat_in_payload__returns_validation_error(
    call_auth_refresh_endpoint, user
):
    # create token without orig_iat in payload
    payload = JSONWebTokenAuthentication.jwt_create_payload(user)
    del payload["orig_iat"]
    auth_token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

    expected_output = {
        "non_field_errors": [_("orig_iat field not found in token.")]
    }

    response = call_auth_refresh_endpoint(auth_token)
    assert response.json() == expected_output


def test_refresh_limit_expired__returns_validation_error(
    call_auth_refresh_endpoint, user
):
    payload = JSONWebTokenAuthentication.jwt_create_payload(user)
    payload["orig_iat"] = 0  # beginning of time
    auth_token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

    expected_output = {"non_field_errors": [_("Refresh has expired.")]}

    response = call_auth_refresh_endpoint(auth_token)
    assert response.json() == expected_output


def test_valid_token__returns_new_token(call_auth_refresh_endpoint, user):
    payload = JSONWebTokenAuthentication.jwt_create_payload(user)
    payload["exp"] = payload["iat"] + 100  # add 100 seconds to issued at time
    auth_token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

    refresh_response = call_auth_refresh_endpoint(auth_token)
    refresh_token = refresh_response.json()["token"]
    assert refresh_token != auth_token


def test_expired_token__returns_validation_error(
    call_auth_refresh_endpoint, user
):
    payload = JSONWebTokenAuthentication.jwt_create_payload(user)
    payload["iat"] = 0
    payload["exp"] = 1
    auth_token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

    expected_output = {"non_field_errors": [_("Token has expired.")]}

    refresh_response = call_auth_refresh_endpoint(auth_token)
    assert refresh_response.json() == expected_output


def test_blacklisted_token__returns_validation_error(
    call_auth_refresh_endpoint, user
):
    payload = JSONWebTokenAuthentication.jwt_create_payload(user)
    auth_token = JSONWebTokenAuthentication.jwt_encode_payload(payload)
    BlacklistedToken.objects.create(
        token=auth_token,
        user=user,
        expires_at=timezone.now() - timedelta(days=7),
    )

    expected_output = {"non_field_errors": [_("Token is blacklisted.")]}

    refresh_response = call_auth_refresh_endpoint(auth_token)
    assert refresh_response.json() == expected_output
