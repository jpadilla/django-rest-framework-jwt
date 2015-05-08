from django.utils.translation import ugettext as _
from rest_framework.authentication import (
    TokenAuthentication,
    get_authorization_header,
)
from rest_framework import exceptions
from rest_framework_jwt.refreshtoken.models import RefreshToken


class RefreshTokenAuthentication(TokenAuthentication):
    """
    Subclassed from rest_framework.authentication.TokenAuthentication

    Auth header:
        Authorization: RefreshToken 401f7ac837da42b97f613d789819ff93537bee6a
    """
    model = RefreshToken

    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != b'refreshtoken':
            return None

        if len(auth) == 1:
            msg = _('Invalid token header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid token header. Token string should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        return self.authenticate_credentials(auth[1])

    def authenticate_credentials(self, key):
        try:
            token = self.model.objects.select_related('user').get(key=key)
        except self.model.DoesNotExist:
            raise exceptions.AuthenticationFailed(_('Invalid token.'))

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))

        return (token.user, token)

    def authenticate_header(self, request):
        return 'RefreshToken'
