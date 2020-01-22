# -*- coding: utf-8 -*-

from __future__ import unicode_literals


try:
    from django.urls import include, url
    from django.utils.translation import gettext as gettext_lazy
except ImportError:
    from django.conf.urls import include, url  # noqa: F401
    from django.utils.translation import ugettext as gettext_lazy
