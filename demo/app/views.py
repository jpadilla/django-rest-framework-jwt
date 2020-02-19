# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from rest_framework.response import Response
from rest_framework.views import APIView

from rest_framework_jwt.blacklist.permissions import IsNotBlacklisted
from rest_framework_jwt.permissions import IsSuperUser


class TestView(APIView):
    def get(self, request):
        return Response({'foo': 'bar'})


class SuperuserTestView(APIView):
    permission_classes = (IsSuperUser, )

    def get(self, request):
        return Response({'foo': 'bar'})


class BlacklistPermissionTestView(APIView):
    permission_classes = (IsNotBlacklisted, )

    def get(self, request):
        return Response({'foo': 'bar'})


test_view = TestView.as_view()
superuser_test_view = SuperuserTestView.as_view()
blacklist_test_view = BlacklistPermissionTestView.as_view()
