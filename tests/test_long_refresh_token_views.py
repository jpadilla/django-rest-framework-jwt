from django.conf.urls import patterns, url
from django.contrib.auth import get_user_model
from django.core.urlresolvers import reverse
from rest_framework import routers
from rest_framework import status
from rest_framework.test import APITestCase

from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt import utils
from rest_framework_jwt.refreshtoken.models import RefreshToken
from rest_framework_jwt.refreshtoken.views import (
    RefreshTokenViewSet,
    DelegateJSONWebToken,
)


User = get_user_model()

RefreshTokenViewSet.authentication_classes = [JSONWebTokenAuthentication]

router = routers.SimpleRouter()
router.register(r'refresh-token', RefreshTokenViewSet)
urlpatterns = router.urls + patterns(
    '',
    url(r'^delegate/$',
        DelegateJSONWebToken.as_view(
            authentication_classes=[JSONWebTokenAuthentication]),
        name='delegate-tokens'),
)


class RefreshTokenTestCase(APITestCase):
    urls = __name__

    def setUp(self):
        self.email = 'jpueblo@example.com'
        self.username = 'jpueblo'
        self.password = 'password'
        self.user = User.objects.create_user(
            self.username, self.email, self.password)
        self.token = RefreshToken.objects.create(user=self.user, app='test-app')
        email1 = 'jonny@example.com'
        username1 = 'jonnytestpants'
        password1 = 'password'
        self.user1 = User.objects.create_user(username1, email1, password1)
        self.token1 = RefreshToken.objects.create(user=self.user1,
                                                  app='another-app')

        self.list_url = reverse('refreshtoken-list')
        self.detail_url = reverse(
            'refreshtoken-detail',
            kwargs={'key': self.token.key}
        )
        self.detail_url1 = reverse(
            'refreshtoken-detail',
            kwargs={'key': self.token1.key}
        )
        self.delegate_url = reverse('delegate-tokens')

    def test_requires_auth(self):
        response = self.client.get(self.list_url)
        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
            (response.status_code, response.content)
        )

        response = self.client.get(self.detail_url)
        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
            (response.status_code, response.content)
        )

        response = self.client.delete(self.detail_url)
        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
            (response.status_code, response.content)
        )

        response = self.client.post(self.list_url)
        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
            (response.status_code, response.content)
        )

    def test_get_refresh_token_list(self):
        self.client.credentials(
            HTTP_AUTHORIZATION='JWT ' + utils.jwt_encode_handler(
                utils.jwt_payload_handler(self.user)))
        response = self.client.get(self.list_url)
        self.assertEqual(len(response.data), 1)
        resp0 = response.data[0]
        self.assertEqual(self.token.key, resp0['key'])

        self.client.force_authenticate(self.user1)
        response = self.client.get(self.list_url)
        self.assertEqual(len(response.data), 1)
        resp0 = response.data[0]
        self.assertEqual(self.token1.key, resp0['key'])

        self.assertEqual(RefreshToken.objects.count(), 2)

    def test_get_refresth_token_detail(self):
        self.client.credentials(
            HTTP_AUTHORIZATION='JWT ' + utils.jwt_encode_handler(
                utils.jwt_payload_handler(self.user)))
        response = self.client.get(self.detail_url)
        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
            (response.status_code, response.content)
        )
        response = self.client.get(self.detail_url1)
        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND,
            (response.status_code, response.content)
        )

    def test_delete_refresth_token(self):
        self.client.credentials(
            HTTP_AUTHORIZATION='JWT ' + utils.jwt_encode_handler(
                utils.jwt_payload_handler(self.user)))
        response = self.client.delete(self.detail_url)
        self.assertEqual(
            response.status_code,
            status.HTTP_204_NO_CONTENT,
            (response.status_code, response.content)
        )
        response = self.client.delete(self.detail_url1)
        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND,
            (response.status_code, response.content)
        )

    def test_create_refresth_token(self):
        data = {
            'app': 'gandolf'
        }
        self.client.credentials(
            HTTP_AUTHORIZATION='JWT ' + utils.jwt_encode_handler(
                utils.jwt_payload_handler(self.user)))
        response = self.client.post(self.list_url, data, format='json')
        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
            (response.status_code, response.content)
        )
        self.assertEqual(response.data['user'], self.user.pk)
        self.assertEqual(response.data['app'], data['app'])

    def test_delegate_jwt(self):
        data = {
            'client_id': 'gandolf',
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'refresh_token': self.token1.key,
            'api_type': 'app',
        }
        response = self.client.post(self.delegate_url,
                                    data=data,
                                    format='json')
        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
            (response.status_code, response.content)
        )
        self.assertIn('token', response.data)

    def test_invalid_body_delegate_jwt(self):
        # client_id is missing
        data = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'refresh_token': self.token1.key,
            'api_type': 'app',
        }
        response = self.client.post(self.delegate_url, data=data,
                                    format='json')
        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
            (response.status_code, response.content)
        )
