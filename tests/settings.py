# -*- coding: utf-8 -*-

DEBUG_PROPAGATE_EXCEPTIONS = True
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'tests.sqlite.db',
    }
}

SITE_ID = 1
SECRET_KEY = 'not very secret in tests'
USE_I18N = True
USE_L10N = True
STATIC_URL = '/static/'
ROOT_URLCONF = 'tests.urls'
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'APP_DIRS': True,
    },
]
MIDDLEWARE = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
)
INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.sites',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework_jwt',
    'tests',
)
PASSWORD_HASHERS = ('django.contrib.auth.hashers.MD5PasswordHasher', )

AUTH_USER_MODEL = 'tests.UserWithProfile'
