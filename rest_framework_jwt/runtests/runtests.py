#!/usr/bin/env python

# https://github.com/tomchristie/django-rest-framework/blob/master/rest_framework/runtests/runtests.py
import os
import sys

# fix sys path so we don't need to setup PYTHONPATH
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
os.environ['DJANGO_SETTINGS_MODULE'] = 'rest_framework_jwt.runtests.settings'

import django
from django.conf import settings
from django.test.utils import get_runner


def main():
    TestRunner = get_runner(settings)

    test_runner = TestRunner()

    test_module_name = 'rest_framework_jwt.tests'

    if django.VERSION[0] == 1 and django.VERSION[1] < 6:
        test_module_name = 'tests'

    failures = test_runner.run_tests(
        [test_module_name], verbosity=1, interactive=True)

    sys.exit(failures)

if __name__ == '__main__':
    main()
