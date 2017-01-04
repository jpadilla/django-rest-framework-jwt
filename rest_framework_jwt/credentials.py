from rest_framework import serializers
from .compat import get_username_field, PasswordField
from django.utils.translation import ugettext as _


class BasicCredentials(object):
    """
    Basic Credentials expects username and password fields.

    """
    @property
    def fields(self):
        fields = dict()
        fields[get_username_field()] = serializers.CharField()
        fields['password'] = PasswordField(write_only=True)
        return fields

    @property
    def validation_message(self):
        msg = _('Must include "{username_field}" and "password".')
        return msg.format(username_field=get_username_field())
