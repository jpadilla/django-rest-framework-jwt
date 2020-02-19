# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from rest_framework import routers

from rest_framework_jwt import views
from rest_framework_jwt.blacklist import views as blacklist_views
from rest_framework_jwt.compat import include, url

from .views import test_view, superuser_test_view, blacklist_test_view

router = routers.DefaultRouter()
router.register(r"blacklist", blacklist_views.BlacklistView, "blacklist")

urlpatterns = [
    url(r"^auth/$", views.obtain_jwt_token, name="auth"),
    url(r"^auth/verify/$", views.verify_jwt_token, name="auth-verify"),
    url(r"^auth/refresh/$", views.refresh_jwt_token, name="auth-refresh"),
    url(r"^impersonate/$", views.impersonate_jwt_token, name="impersonate"),
    url(r"^test-view/$", test_view, name="test-view"),
    url(r"^superuser-test-view/$", superuser_test_view, name="superuser-test-view"),
    url(r"^blacklist-test-view/$", blacklist_test_view, name="blacklist-test-view"),
    url(r"^", include(router.urls)),
]
