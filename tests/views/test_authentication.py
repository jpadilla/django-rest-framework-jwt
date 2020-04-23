# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from base64 import b64encode

from collections import OrderedDict

from django.utils.encoding import force_str
from django.utils.translation import ugettext_lazy as _

from jwt import get_unverified_header
from jwt.exceptions import InvalidKeyError, InvalidAlgorithmError, InvalidSignatureError

from pytest import skip, fixture, raises

from rest_framework import status

from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.compat import gettext_lazy as _
from rest_framework_jwt.compat import has_set_cookie_samesite
from rest_framework_jwt.settings import api_settings

from sys import version_info

@fixture
def rsa_keys(scope="session"):
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    nkeys = 2
    secret = {}
    public = {}

    for i in range(1, nkeys + 1):
        name = "rsa%d" % i
        secret[name] = rsa.generate_private_key(
            public_exponent=65537,
            # key_size=512 is probably unsafe for any real world code!
            key_size=512,
            backend=default_backend()
        )
        public[name] = secret[name].public_key()

    rsa_keys = {"secret": secret, "public": public}
    return rsa_keys

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
    assert "token" in force_str(response.content)
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


def test_multi_keys_hash_hash(
    monkeypatch, user, call_auth_endpoint
):
    monkeypatch.setattr(api_settings, "JWT_SECRET_KEY", ["key1", "key2"])

    response = call_auth_endpoint("username", "password")
    token = response.json()["token"]

    monkeypatch.setattr(api_settings, "JWT_SECRET_KEY", ["key2", "key1"])

    payload = JSONWebTokenAuthentication.jwt_decode_token(token)

    assert response.status_code == status.HTTP_200_OK
    assert payload["user_id"] == user.id
    assert payload["username"] == user.get_username()


def test_multi_keys_rsa_rsa(
    monkeypatch, user, call_auth_endpoint, rsa_keys
):

    monkeypatch.setattr(api_settings, "JWT_ALGORITHM", "RS256")
    monkeypatch.setattr(
        api_settings, "JWT_PUBLIC_KEY", list(rsa_keys["public"].values())
    )

    for skey in rsa_keys["secret"].values():
        monkeypatch.setattr(api_settings, "JWT_PRIVATE_KEY", skey)

        response = call_auth_endpoint("username", "password")
        token = response.json()["token"]

        payload = JSONWebTokenAuthentication.jwt_decode_token(token)

        assert response.status_code == status.HTTP_200_OK
        assert payload["user_id"] == user.id
        assert payload["username"] == user.get_username()


def test_signing_and_acceptance_of_multiple_algorithms(
    monkeypatch, user, call_auth_endpoint, rsa_keys
):

    monkeypatch.setattr(
        api_settings, "JWT_PRIVATE_KEY", rsa_keys["secret"]["rsa1"]
    )
    monkeypatch.setattr(
        api_settings, "JWT_PUBLIC_KEY", rsa_keys["public"]["rsa1"]
    )

    for algo in [["HS256", "RS256"], ["RS256", "HS256"]]:
        monkeypatch.setattr(api_settings, "JWT_ALGORITHM", algo)

        response = call_auth_endpoint("username", "password")
        token = response.json()["token"]

        # check needs to succeed no matter which algo is first
        algo = [algo[1], algo[0]]
        monkeypatch.setattr(api_settings, "JWT_ALGORITHM", algo)
        payload = JSONWebTokenAuthentication.jwt_decode_token(token)

        assert response.status_code == status.HTTP_200_OK
        assert payload["user_id"] == user.id
        assert payload["username"] == user.get_username()

        # changing the signature raises exception
        token += "a"
        with raises(InvalidSignatureError):
            assert JSONWebTokenAuthentication.jwt_decode_token(token) == None



def test_keys_with_key_id(
    monkeypatch, user, call_auth_endpoint, rsa_keys
):

    monkeypatch.setattr(
        api_settings, "JWT_PRIVATE_KEY", { "rsa1": rsa_keys["secret"]["rsa1"] }
    )
    monkeypatch.setattr(
        api_settings, "JWT_PUBLIC_KEY", rsa_keys["public"]
    )

    secret_key = OrderedDict([("hash1", "one"), ("hash2", "two")])
    monkeypatch.setattr(api_settings, "JWT_SECRET_KEY", secret_key)

    for kid, algo in {"hash1": ["HS256", "RS256"], "rsa1": ["RS256", "HS256"]}.items():
        monkeypatch.setattr(api_settings, "JWT_ALGORITHM", algo)

        response = call_auth_endpoint("username", "password")
        token = response.json()["token"]

        # check needs to succeed no matter which algo is first
        algo = [algo[1], algo[0]]
        monkeypatch.setattr(api_settings, "JWT_ALGORITHM", algo)
        payload = JSONWebTokenAuthentication.jwt_decode_token(token)
        hdr = get_unverified_header(token)

        assert hdr["kid"] == kid
        assert response.status_code == status.HTTP_200_OK
        assert payload["user_id"] == user.id
        assert payload["username"] == user.get_username()

def test_keys_key_id_not_found(
    monkeypatch, user, call_auth_endpoint
):

    secret_key = OrderedDict([("hash1", "one"), ("hash2", "two")])
    monkeypatch.setattr(api_settings, "JWT_SECRET_KEY", secret_key)

    response = call_auth_endpoint("username", "password")
    token = response.json()["token"]

    secret_key = OrderedDict(hash3="three")
    monkeypatch.setattr(api_settings, "JWT_SECRET_KEY", secret_key)

    with raises(InvalidKeyError):
        assert JSONWebTokenAuthentication.jwt_decode_token(token) == None

def test_insist_on_key_id(
    monkeypatch, user, call_auth_endpoint
):

    secret = "averybadone"

    monkeypatch.setattr(api_settings, "JWT_SECRET_KEY", secret)

    response = call_auth_endpoint("username", "password")
    assert response.status_code == status.HTTP_200_OK

    token = response.json()["token"]

    # check if key is still accepted when giving it a name
    monkeypatch.setattr(api_settings, "JWT_SECRET_KEY", {"kid": secret})

    payload = JSONWebTokenAuthentication.jwt_decode_token(token)
    assert payload["user_id"] == user.id
    assert payload["username"] == user.get_username()

    # check if we insist on the key beging named
    monkeypatch.setattr(api_settings, "JWT_INSIST_ON_KID", True)
    with raises(InvalidKeyError):
        assert JSONWebTokenAuthentication.jwt_decode_token(token) == None

def test_InvalidAlgorithmError():

    hdr = '{"alg": "bad", "typ": "JWT"}'
    jwt = b64encode(hdr.encode("ascii")) + "..".encode("ascii")

    with raises(InvalidAlgorithmError):
        assert JSONWebTokenAuthentication.jwt_decode_token(jwt) == None
