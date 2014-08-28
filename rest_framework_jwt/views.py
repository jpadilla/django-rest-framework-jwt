from rest_framework.views import APIView
from rest_framework import status
from rest_framework import parsers
from rest_framework import renderers
from rest_framework.response import Response

from .serializers import JSONWebTokenSerializer, RefreshJSONWebTokenSerializer


class ObtainJSONWebToken(APIView):
    """
    API View that receives a POST with a user's username and password.

    Returns a JSON Web Token that can be used for authenticated requests.
    """
    throttle_classes = ()
    permission_classes = ()
    authentication_classes = ()
    parser_classes = (parsers.FormParser, parsers.JSONParser,)
    renderer_classes = (renderers.JSONRenderer,)
    serializer_class = JSONWebTokenSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.DATA)
        if serializer.is_valid():
            return Response({'token': serializer.object['token']})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RefreshJSONWebToken(APIView):
    """
    API View that returns a refreshed token (with new expiration) based on
    existing token

    If 'orig_iat' field (original issued-at-time) is found, will first check
    if it's within expiration window, then copy it to the new token
    """
    throttle_classes = ()
    permission_classes = ()
    authentication_classes = ()
    parser_classes = (parsers.FormParser, parsers.JSONParser,)
    renderer_classes = (renderers.JSONRenderer,)
    serializer_class = RefreshJSONWebTokenSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.DATA)
        if serializer.is_valid():
            return Response({'token': serializer.object['token']})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


obtain_jwt_token = ObtainJSONWebToken.as_view()
refresh_jwt_token = RefreshJSONWebToken.as_view()
