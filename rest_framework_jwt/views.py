from rest_framework.views import APIView
from rest_framework import status
from rest_framework import parsers
from rest_framework import renderers
from rest_framework.response import Response

from .serializers import JSONWebTokenSerializer


class ObtainJSONWebToken(APIView):
    """
    API View that receives a POST with a user's username and password.

    Returns a JSON Web Token that can be used for authenticated requests.
    """
    throttle_classes = ()
    permission_classes = ()
    parser_classes = (parsers.FormParser, parsers.JSONParser,)
    renderer_classes = (renderers.JSONRenderer,)
    serializer_class = JSONWebTokenSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.DATA)
        if serializer.is_valid():
            return Response({'token': serializer.object['token']})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


obtain_jwt_token = ObtainJSONWebToken.as_view()
