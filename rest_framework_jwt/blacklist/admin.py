from django.contrib import admin

from rest_framework_jwt.settings import api_settings

from . import models


class JWTBlacklistTokenAdmin(admin.ModelAdmin):
    list_display = ('jti', 'expires', 'created', 'is_active')
    fields = ('jti', 'expires', 'created', 'is_active')
    readonly_fields = ('jti', 'expires', 'created', 'is_active')

    def is_active(self, obj):
        return obj.is_active()
    is_active.boolean = True
    is_active.short_description = 'Active'

if api_settings.JWT_ENABLE_BLACKLIST:
    admin.site.register(models.JWTBlacklistToken, JWTBlacklistTokenAdmin)
