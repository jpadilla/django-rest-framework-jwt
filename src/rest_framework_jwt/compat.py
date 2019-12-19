# -*- coding: utf-8 -*-

from __future__ import unicode_literals


try:
    from django.urls import include, url
except ImportError:
    from django.conf.urls import include, url  # noqa: F401
