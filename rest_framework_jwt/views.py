from django.utils.encoding import force_text
from django.utils.translation import ugettext_lazy as _
from rest_framework import mixins, status, viewsets
from rest_framework.exceptions import APIException, NotFound
from rest_framework.generics import DestroyAPIView
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from datetime import datetime

from .models import Device
from .settings import api_settings
from .serializers import (
    DeviceSerializer, DeviceTokenRefreshSerializer, JSONWebTokenSerializer, RefreshJSONWebTokenSerializer,
    VerifyJSONWebTokenSerializer
)

jwt_response_payload_handler = api_settings.JWT_RESPONSE_PAYLOAD_HANDLER


class HeaderDisallowed(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = _('Using the {header} header is disallowed for {view_name}.')

    def __init__(self, header, view_name, detail=None):
        self.detail = force_text(self.default_detail).format(header=header, view_name=view_name)


class HeadersCheckMixin(object):
    def initial(self, request, *args, **kwargs):
        if (api_settings.JWT_PERMANENT_TOKEN_AUTH and request.META.get('permanent_token') and
                type(self) != DeviceRefreshJSONWebToken):
            raise HeaderDisallowed('permanent_token', type(self).__name__)
        super(HeadersCheckMixin, self).initial(request, *args, **kwargs)


class JSONWebTokenAPIView(HeadersCheckMixin, APIView):
    """
    Base API View that various JWT interactions inherit from.
    """
    permission_classes = ()
    authentication_classes = ()

    def get_serializer_context(self):
        """
        Extra context provided to the serializer class.
        """
        return {
            'request': self.request,
            'view': self,
        }

    def get_serializer_class(self):
        """
        Return the class to use for the serializer.
        Defaults to using `self.serializer_class`.
        You may want to override this if you need to provide different
        serializations depending on the incoming request.
        (Eg. admins get full serialization, others get basic serialization)
        """
        assert self.serializer_class is not None, (
            "'%s' should either include a `serializer_class` attribute, "
            "or override the `get_serializer_class()` method."
            % self.__class__.__name__)
        return self.serializer_class

    def get_serializer(self, *args, **kwargs):
        """
        Return the serializer instance that should be used for validating and
        deserializing input, and for serializing output.
        """
        serializer_class = self.get_serializer_class()
        kwargs['context'] = self.get_serializer_context()
        return serializer_class(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            user = serializer.object.get('user') or request.user
            token = serializer.object.get('token')
            device = serializer.object.get('device', None)
            kwargs = {}
            if device:
                kwargs.update(dict(permanent_token=device.permanent_token, device_id=device.id))

            response_data = jwt_response_payload_handler(token, user, request, **kwargs)
            response = Response(response_data)
            if api_settings.JWT_AUTH_COOKIE:
                expiration = (datetime.utcnow() +
                              api_settings.JWT_EXPIRATION_DELTA)
                response.set_cookie(api_settings.JWT_AUTH_COOKIE,
                                    token,
                                    expires=expiration,
                                    httponly=True)
            return response

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ObtainJSONWebToken(JSONWebTokenAPIView):
    """
    API View that receives a POST with a user's username and password.

    Returns a JSON Web Token that can be used for authenticated requests.
    """
    serializer_class = JSONWebTokenSerializer


class VerifyJSONWebToken(JSONWebTokenAPIView):
    """
    API View that checks the veracity of a token, returning the token if it
    is valid.
    """
    serializer_class = VerifyJSONWebTokenSerializer


class RefreshJSONWebToken(JSONWebTokenAPIView):
    """
    API View that returns a refreshed token (with new expiration) based on
    existing token

    If 'orig_iat' field (original issued-at-time) is found, will first check
    if it's within expiration window, then copy it to the new token
    """
    serializer_class = RefreshJSONWebTokenSerializer


class DeviceRefreshJSONWebToken(HeadersCheckMixin, APIView):
    """
    API View used to refresh JSON Web Token using permanent token.
    """
    serializer_class = DeviceTokenRefreshSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.META)
        if serializer.is_valid(raise_exception=True):
            data = jwt_response_payload_handler(request=request, **serializer.validated_data)
            return Response(data, status=status.HTTP_200_OK)


class DeviceLogout(HeadersCheckMixin, DestroyAPIView):
    """
    Logout user by deleting Device.
    """
    queryset = Device.objects.all()
    permission_classes = [IsAuthenticated]

    def get_object(self):
        try:
            return self.get_queryset().get(user=self.request.user, id=self.request.META.get('device_id'))
        except Device.DoesNotExist:
            raise NotFound(_('Device does not exist.'))


class DeviceViewSet(HeadersCheckMixin, mixins.ListModelMixin, mixins.DestroyModelMixin, viewsets.GenericViewSet):
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return self.queryset.filter(user=self.request.user)


obtain_jwt_token = ObtainJSONWebToken.as_view()
refresh_jwt_token = RefreshJSONWebToken.as_view()
verify_jwt_token = VerifyJSONWebToken.as_view()
device_refresh_token = DeviceRefreshJSONWebToken.as_view()
device_logout = DeviceLogout.as_view()
