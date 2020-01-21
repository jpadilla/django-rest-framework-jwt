from django.db import models


class BlacklistedToken(models.Model):
    token = models.TextField()
    blacklisted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return 'Blacklisted token - {}'.format(self.token)
