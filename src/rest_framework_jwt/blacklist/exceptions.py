# -*- coding: utf-8 -*-

from rest_framework.exceptions import APIException


class TokenMissing(APIException):
    status_code = 400
    default_detail = 'The token is missing.'
    default_code = 'token_missing'
