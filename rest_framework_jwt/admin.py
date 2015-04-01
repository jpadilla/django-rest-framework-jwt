from django.contrib import admin

from rest_framework_jwt.settings import api_settings

from . import models


class JWTBlacklistTokenAdmin(admin.ModelAdmin):
    list_display = ('jti', 'expires', 'created', 'is_expired')
    fields = ('jti', 'expires', 'created', 'is_expired')
    readonly_fields = ('jti', 'expires', 'created', 'is_expired')

    def is_expired(self, obj):
        return obj.is_expired()
    is_expired.boolean = True

if api_settings.JWT_ENABLE_BLACKLIST:
    admin.site.register(models.JWTBlacklistToken, JWTBlacklistTokenAdmin)
