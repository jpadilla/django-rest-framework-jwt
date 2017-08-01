from django.conf.urls import url
from django.http import HttpResponse
from rest_framework import permissions, routers
from rest_framework.views import APIView
try:
    from rest_framework_oauth.authentication import OAuth2Authentication
except ImportError:
    try:
        from rest_framework.authentication import OAuth2Authentication
    except ImportError:
        OAuth2Authentication = None

from rest_framework_jwt import views
from rest_framework_jwt.authentication import JSONWebTokenAuthentication


class MockView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        return HttpResponse({'a': 1, 'b': 2, 'c': 3})

    def post(self, request):
        return HttpResponse({'a': 1, 'b': 2, 'c': 3})


router = routers.SimpleRouter()
router.register(r'devices', views.DeviceViewSet)

urlpatterns = [
    url(r'^auth-token/$', views.obtain_jwt_token),
    url(r'^auth-token-refresh/$', views.refresh_jwt_token),
    url(r'^auth-token-verify/$', views.verify_jwt_token),
    url(r'^device-refresh-token/$', views.device_refresh_token),
    url(r'^device-logout/$', views.device_logout),

    url(r'^jwt/$', MockView.as_view(
        authentication_classes=[JSONWebTokenAuthentication])),
    url(r'^jwt-oauth2/$', MockView.as_view(
        authentication_classes=[
            JSONWebTokenAuthentication, OAuth2Authentication])),
    url(r'^oauth2-jwt/$', MockView.as_view(
        authentication_classes=[
            OAuth2Authentication, JSONWebTokenAuthentication])),
] + router.urls
