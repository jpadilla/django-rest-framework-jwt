from django.db import IntegrityError

from rest_framework.exceptions import ValidationError
from rest_framework.viewsets import ModelViewSet

from rest_framework_jwt.blacklist.models import BlacklistedToken

from ..authentication import JSONWebTokenAuthentication
from .permissions import CanBlacklist
from .serializers import BlacklistTokenSerializer


class BlacklistView(ModelViewSet):
    permission_classes = (CanBlacklist, )
    authentication_classes = (JSONWebTokenAuthentication, )
    queryset = BlacklistedToken.objects.all().order_by('-blacklisted_at')
    serializer_class = BlacklistTokenSerializer

    def create(self, request, *args, **kwargs):
        try:
            if 'user' not in request.data:
                # This case should occur only when this view is used at logout.
                request.data.update({'user': request.user.id})
            return super(BlacklistView, self).create(request, *args, **kwargs)
        except IntegrityError:
            raise ValidationError('User\'s token has already been blacklisted.')
