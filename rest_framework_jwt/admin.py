from django.contrib import admin

from . import models


class JWTBlackListTokenAdmin(admin.ModelAdmin):
    list_display = ('jti', 'expires', 'created', 'is_expired')
    fields = ('jti', 'expires', 'created', 'is_expired')
    readonly_fields = ('jti', 'expires', 'created', 'is_expired')

    def is_expired(self, obj):
        return obj.is_expired()
    is_expired.boolean = True

admin.site.register(models.JWTBlackListToken, JWTBlackListTokenAdmin)
