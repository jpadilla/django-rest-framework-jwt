from .base import *


DEBUG = False
DEBUG_PROPAGATE_EXCEPTIONS = True
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "tests.sqlite.db",
    }
}
PASSWORD_HASHERS = ("django.contrib.auth.hashers.MD5PasswordHasher",)
