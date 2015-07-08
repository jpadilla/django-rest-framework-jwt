from django.db.models import get_model
from django.conf import settings
from django.contrib import admin

from . import models


class JWTBlacklistTokenAdmin(admin.ModelAdmin):
    list_display = ('jti', 'expires', 'created', 'is_active')
    fields = ('jti', 'expires', 'created', 'is_active')
    readonly_fields = ('jti', 'expires', 'created', 'is_active')

    def is_active(self, obj):
        return obj.is_active()
    is_active.boolean = True
    is_active.short_description = 'Active'

if 'rest_framework_jwt.blacklist' in settings.INSTALLED_APPS:
    try:
        get_model('blacklist', 'jwtblacklisttoken')
    except Exception:
        pass
    else:
        admin.site.register(models.JWTBlacklistToken, JWTBlacklistTokenAdmin)
