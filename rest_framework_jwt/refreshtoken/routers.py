from rest_framework import routers
from django.conf.urls import patterns, url

from .views import RefreshTokenViewSet, DelegateJSONWebToken

router = routers.SimpleRouter()
router.register(r'refresh-token', RefreshTokenViewSet)

urlpatterns = router.urls + patterns('',  # NOQA
    url(r'^delegate/$', DelegateJSONWebToken.as_view(), name='delegate-tokens'),
)
