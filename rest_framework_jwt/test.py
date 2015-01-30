from rest_framework.test import APITestCase, APIClient
from rest_framework import status


class APIJWTClient(APIClient):
    def login(self, username, password):
        """
        Returns True if login is possible; False if the provided credentials
        are incorrect, or the user is inactive.
        """
        response = self.post('/api-token-auth/', {"username": username, "password": password},
                             format='json')
        if response.status_code == status.HTTP_200_OK:
            self.credentials(HTTP_AUTHORIZATION='JWT ' + response.data['token'])

            return True
        else:
            return False


class APIJWTTestCase(APITestCase):
    client_class = APIJWTClient
