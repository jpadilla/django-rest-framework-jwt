# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from rest_framework_jwt import views
from rest_framework_jwt.compat import url

from .views import test_view, superuser_test_view

urlpatterns = [
    url(r"^auth/$", views.obtain_jwt_token, name="auth"),
    url(r"^auth/verify/$", views.verify_jwt_token, name="auth-verify"),
    url(r"^auth/refresh/$", views.refresh_jwt_token, name="auth-refresh"),
    url(r"^test-view/$", test_view, name="test-view"),
    url(r"^superuser-test-view/$", superuser_test_view, name="superuser-test-view"),
    url(r"^impersonate/$", views.impersonate_jwt_token, name="impersonate"),
]
