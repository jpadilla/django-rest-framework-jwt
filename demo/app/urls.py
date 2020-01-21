# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django.conf.urls import include
from rest_framework import routers
from rest_framework_jwt import views
from rest_framework_jwt.compat import url

from .views import test_view
from rest_framework_jwt.blacklist import views as blacklist_views


router = routers.DefaultRouter()
router.register(r"blacklist", blacklist_views.BlacklistView, basename="blacklist")

urlpatterns = [
    url(r"^auth/$", views.obtain_jwt_token, name="auth"),
    url(r"^auth/verify/$", views.verify_jwt_token, name="auth-verify"),
    url(r"^auth/refresh/$", views.refresh_jwt_token, name="auth-refresh"),
    url(r"^test-view/$", test_view, name="test-view"),
    url(r'^', include((router.urls, "blacklist"), namespace="blacklist")),
]
