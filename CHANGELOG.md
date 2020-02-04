# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

Changes for the upcoming release can be found in the `changelog.d` directory in
this repository.

Do **NOT** add changelog entries here! This changelog is managed by
[towncrier](https://github.com/hawkowl/towncrier) and is compiled at release
time.

.. towncrier release notes start

1.14.0 (2020-01-29)
====================

Features
--------

- Impersonation allows the service to perform actions on the client’s behalf. A typical use case would be troubleshooting. We can act like the user who submitted an issue without requiring its login credentials. ([#26](https://github.com/Styria-Digital/django-rest-framework-jwt/pull/26))
- added `JWT_AUTH_COOKIE_*` settings paralleling Django's
  `SESSION_COOKIE_*` which are used for `JWT_AUTH_COOKIE` and
  `JWT_IMPERSONATION_COOKIE`

  This changes the default `Secure` attribute from `False` to
  `True`. Users wishing to use JWT cookies over http (as in no TLS/SSL)
  need to set `JWT_AUTH_COOKIE_SECURE` to `False.`

  This change is intentional to follow common best common practice.

  With Django versions >= 2.1.0, the `Samesite` attribute is set to
  `Lax` by default. ([#29](https://github.com/Styria-Digital/django-rest-framework-jwt/pull/29))


Improved Documentation
----------------------

- Document compatibility with Python 3.7. ([#23](https://github.com/Styria-Digital/django-rest-framework-jwt/pull/23))
- Add support for Django 3.0, Python 3.8 and `djangorestframework` 3.11 ([#24](https://github.com/Styria-Digital/django-rest-framework-jwt/pull/24))


Misc
----

- * Run the test suite against the `demo` project. The same project can be used for local development as well.
  * Add the `serve` environment to `tox` that starts the `demo` project's development server. To use it, run: `$ tox -e serve` ([#24](https://github.com/Styria-Digital/django-rest-framework-jwt/pull/24))


1.13.4 (2019-12-13)
====================

Bugfixes
--------

- Remove serialization on response data in `BaseJSONWebTokenAPIView` because it 
  breaks custom response payload handlers which add extra data to the response 
  payload. This change aligns this fork more closely with the original and makes 
  it easier to use this fork as a drop-in replacement for the original. Also 
  change the ReponsePayload from a `namedtuple` to a dictionary because 
  `namedtuple` is not JSON serializable ([#22](https://github.com/Styria-Digital/django-rest-framework-jwt/pull/22))


1.13.3 (2019-10-17)
====================

Features
--------

- - Added support for djangorestframework 3.10 ([#18](https://github.com/Styria-Digital/django-rest-framework-jwt/pull/18))
- Allow control of setting the `user_id` in the payload with `JWT_PAYLOAD_INCLUDE_USER_ID`. ([#20](https://github.com/Styria-Digital/django-rest-framework-jwt/pull/20))


1.13.2 (2019-08-26)
====================

Bugfixes
--------

- Use pk to get profile's id in `rest_framework_jwt.utils.jwt_create_payload`. ([#15](https://github.com/Styria-Digital/django-rest-framework-jwt/pull/15))


1.13.1 (2019-08-23)
====================

Bugfixes
--------

- Pass `request` to `django.contrib.auth.authenticate`. ([#14](https://github.com/Styria-Digital/django-rest-framework-jwt/pull/14))


1.13.0 (2019-04-23)
=====================

Features
--------

- Added `on_delete` to `tests.models.UserProfile.user` required by Django 2.2,
  and added Django 2.x, Python 3.7 and djangorestframework 3.9 to the support matrix. ([#9](https://github.com/Styria-Digital/django-rest-framework-jwt/pull/9))


1.12.10 (2018-12-21)
====================

No significant changes.


1.12.9 (2018-12-21)
====================

Misc
----

- Fixed inconsistent View names. ([#7](https://github.com/Styria-Digital/django-rest-framework-jwt/pull/7))


1.12.8 (2018-12-21)
====================

Misc
----

- Updated docs. Drop support for Django < 1.8 and DRF < 3.7.x. ([#6](https://github.com/Styria-Digital/django-rest-framework-jwt/pull/6))


1.12.7 (2018-12-17)
====================

Misc
----

- Switch to Travis CI build stages ([#3](https://github.com/Styria-Digital/django-rest-framework-jwt/pull/3))


1.12.3 (2018-12-13)
====================

Misc
----

- Project restructuring according to SDS code style and conventions. ([#2](https://github.com/Styria-Digital/django-rest-framework-jwt/pull/2))
