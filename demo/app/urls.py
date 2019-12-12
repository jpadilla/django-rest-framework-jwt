# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django.conf.urls import url

from rest_framework_jwt import views
from .views import test_view

urlpatterns = [
    url(r'^auth/$', views.obtain_jwt_token, name='auth'),
    url(r'^auth/verify/$', views.verify_jwt_token, name='auth-verify'),
    url(r'^auth/refresh/$', views.refresh_jwt_token, name='auth-refresh'),
    url(r'^test-view/$', test_view, name='test-view'),
    url(r'^impersonate/$', views.impersonation_view, name='impersonate')
]
