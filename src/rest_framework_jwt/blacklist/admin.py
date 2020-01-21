from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from .models import BlacklistedToken


class BlacklistedTokenAdmin(admin.ModelAdmin):
    list_display = ('token', )


admin.site.register(BlacklistedToken, BlacklistedTokenAdmin)
