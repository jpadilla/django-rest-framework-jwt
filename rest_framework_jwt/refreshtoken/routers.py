from rest_framework import routers
from django.conf.urls import patterns, url

from .views import RefreshTokenViewSet, DelagateJSONWebToken

router = routers.SimpleRouter()
router.register(r'refresh-token', RefreshTokenViewSet)

urlpatterns = router.urls + patterns('',  # NOQA
    url(r'delgate/$', DelagateJSONWebToken.as_view(), name='delgate-tokens'),
)
