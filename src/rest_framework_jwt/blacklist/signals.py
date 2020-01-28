from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import BlacklistedToken


@receiver(post_save, sender=BlacklistedToken)
def delete_stale_tokens(sender, instance, **kwargs):
    BlacklistedToken.objects.delete_stale_tokens()
