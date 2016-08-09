"""
Blank URLConf just to keep the test suite happy
"""
try:
    from django.conf.urls import patterns
    urlpatterns = patterns('')
except ImportError:
    urlpatterns = []
