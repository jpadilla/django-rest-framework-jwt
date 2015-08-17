# Change Log

## [1.7.0](https://github.com/GetBlimp/django-rest-framework-jwt/tree/1.7.0) (2015-08-17)
[Full Changelog](https://github.com/GetBlimp/django-rest-framework-jwt/compare/1.6.0...1.7.0)

**Implemented enhancements:**

- Password form field uses type="text" [\#133](https://github.com/GetBlimp/django-rest-framework-jwt/issues/133)
- Support Reading the JWT from the Requests Cookies [\#120](https://github.com/GetBlimp/django-rest-framework-jwt/issues/120)

**Fixed bugs:**

- Method utils.jwt\_payload\_handler ignores USERNAME\_FIELD [\#128](https://github.com/GetBlimp/django-rest-framework-jwt/issues/128)

**Closed issues:**

- Custom Payload Fields [\#145](https://github.com/GetBlimp/django-rest-framework-jwt/issues/145)
- DATA deprecated in DRF 3.2.1 [\#143](https://github.com/GetBlimp/django-rest-framework-jwt/issues/143)
- ImportError: cannot import name 'smart\_text' [\#141](https://github.com/GetBlimp/django-rest-framework-jwt/issues/141)
- `NotImplementedError` on accessing `request.DATA` [\#139](https://github.com/GetBlimp/django-rest-framework-jwt/issues/139)
- Throttling [\#135](https://github.com/GetBlimp/django-rest-framework-jwt/issues/135)
- error: orig\_iat field is required [\#134](https://github.com/GetBlimp/django-rest-framework-jwt/issues/134)
- Docs do not mention imports [\#132](https://github.com/GetBlimp/django-rest-framework-jwt/issues/132)
- Get token if email confirmed [\#131](https://github.com/GetBlimp/django-rest-framework-jwt/issues/131)
- Implement password reset mechanisim [\#130](https://github.com/GetBlimp/django-rest-framework-jwt/issues/130)
- Installing fails - file name too long [\#129](https://github.com/GetBlimp/django-rest-framework-jwt/issues/129)
- Add BrowsableAPIRenderer to views? [\#126](https://github.com/GetBlimp/django-rest-framework-jwt/issues/126)
- Enable expiration by user [\#125](https://github.com/GetBlimp/django-rest-framework-jwt/issues/125)
- Expire tokens on logout [\#116](https://github.com/GetBlimp/django-rest-framework-jwt/issues/116)
- 'JWT\_PAYLOAD\_GET\_USER\_ID\_HANDLER' to 'JWT\_PAYLOAD\_GET\_PK\_HANDLER' [\#111](https://github.com/GetBlimp/django-rest-framework-jwt/issues/111)
- OperationalError: no such table: auth\_user [\#97](https://github.com/GetBlimp/django-rest-framework-jwt/issues/97)
- Allow JWT\_AUDIENCE to be a list of Strings [\#96](https://github.com/GetBlimp/django-rest-framework-jwt/issues/96)

**Merged pull requests:**

- remove throttle override in JSONWebTokenAPIView [\#138](https://github.com/GetBlimp/django-rest-framework-jwt/pull/138) ([resalisbury](https://github.com/resalisbury))

## [1.6.0](https://github.com/GetBlimp/django-rest-framework-jwt/tree/1.6.0) (2015-06-12)
[Full Changelog](https://github.com/GetBlimp/django-rest-framework-jwt/compare/1.5.0...1.6.0)

**Closed issues:**

- ObtainJSONWebToken post method should return 401 status code for invalid credentials [\#107](https://github.com/GetBlimp/django-rest-framework-jwt/issues/107)
- verify token returns a fresh jwt token. [\#106](https://github.com/GetBlimp/django-rest-framework-jwt/issues/106)
- InvalidAudienceError results in 500 Error Rather than 401/403 [\#100](https://github.com/GetBlimp/django-rest-framework-jwt/issues/100)

**Merged pull requests:**

- run tests only against latest minor version [\#122](https://github.com/GetBlimp/django-rest-framework-jwt/pull/122) ([ticosax](https://github.com/ticosax))
- Added the ability to use custom renderers for the JWT endpoints. [\#121](https://github.com/GetBlimp/django-rest-framework-jwt/pull/121) ([Jwpe](https://github.com/Jwpe))
- Some specialized serializers needs the request in context. [\#119](https://github.com/GetBlimp/django-rest-framework-jwt/pull/119) ([ticosax](https://github.com/ticosax))
- Drf 2.x.x and dj1.8 not supported [\#118](https://github.com/GetBlimp/django-rest-framework-jwt/pull/118) ([ticosax](https://github.com/ticosax))
- Verify should not refresh [\#109](https://github.com/GetBlimp/django-rest-framework-jwt/pull/109) ([ticosax](https://github.com/ticosax))
- 2 seconds is an eternity [\#108](https://github.com/GetBlimp/django-rest-framework-jwt/pull/108) ([ticosax](https://github.com/ticosax))

## [1.5.0](https://github.com/GetBlimp/django-rest-framework-jwt/tree/1.5.0) (2015-04-28)
[Full Changelog](https://github.com/GetBlimp/django-rest-framework-jwt/compare/1.4.0...1.5.0)

**Implemented enhancements:**

- Add support for specifying scopes [\#55](https://github.com/GetBlimp/django-rest-framework-jwt/issues/55)
- Allow view arguments to override default settings [\#54](https://github.com/GetBlimp/django-rest-framework-jwt/issues/54)
- Make it a little easier to customize user [\#53](https://github.com/GetBlimp/django-rest-framework-jwt/issues/53)
- email/password should be a valid login combination just like username/password is. [\#34](https://github.com/GetBlimp/django-rest-framework-jwt/issues/34)

**Fixed bugs:**

- Custom User is not handled correctly [\#36](https://github.com/GetBlimp/django-rest-framework-jwt/issues/36)

**Closed issues:**

- Should getting a token require POST? [\#104](https://github.com/GetBlimp/django-rest-framework-jwt/issues/104)
- verify\_expiration no longer supported by pyJWT [\#103](https://github.com/GetBlimp/django-rest-framework-jwt/issues/103)
- JWT\_ALLOW\_REFRESH working? [\#98](https://github.com/GetBlimp/django-rest-framework-jwt/issues/98)
- TypeError: verify\_signature\(\) got an unexpected keyword argument 'algorithms' [\#93](https://github.com/GetBlimp/django-rest-framework-jwt/issues/93)
- Allow token invalidation [\#87](https://github.com/GetBlimp/django-rest-framework-jwt/issues/87)
- Handle jwt Issued by Another Service [\#76](https://github.com/GetBlimp/django-rest-framework-jwt/issues/76)

**Merged pull requests:**

- add python 3.2 to tox tests [\#99](https://github.com/GetBlimp/django-rest-framework-jwt/pull/99) ([JocelynDelalande](https://github.com/JocelynDelalande))
- Test against django1.8 and drf 3.1.0 [\#95](https://github.com/GetBlimp/django-rest-framework-jwt/pull/95) ([ticosax](https://github.com/ticosax))
- propagate request arg in all the doc strings [\#90](https://github.com/GetBlimp/django-rest-framework-jwt/pull/90) ([kvbik](https://github.com/kvbik))

## [1.4.0](https://github.com/GetBlimp/django-rest-framework-jwt/tree/1.4.0) (2015-03-18)
[Full Changelog](https://github.com/GetBlimp/django-rest-framework-jwt/compare/1.3.2...1.4.0)

## [1.3.2](https://github.com/GetBlimp/django-rest-framework-jwt/tree/1.3.2) (2015-03-15)
[Full Changelog](https://github.com/GetBlimp/django-rest-framework-jwt/compare/1.3.1...1.3.2)

**Implemented enhancements:**

- QueryParameterAuthentication [\#71](https://github.com/GetBlimp/django-rest-framework-jwt/issues/71)

**Closed issues:**

- No packaged file at version 1.3.0 [\#86](https://github.com/GetBlimp/django-rest-framework-jwt/issues/86)

**Merged pull requests:**

- Use only ASCII characters in README.rst [\#88](https://github.com/GetBlimp/django-rest-framework-jwt/pull/88) ([fantastic001](https://github.com/fantastic001))

## [1.3.1](https://github.com/GetBlimp/django-rest-framework-jwt/tree/1.3.1) (2015-03-10)
[Full Changelog](https://github.com/GetBlimp/django-rest-framework-jwt/compare/1.3.0...1.3.1)

**Closed issues:**

- test.py [\#85](https://github.com/GetBlimp/django-rest-framework-jwt/issues/85)
- Token verification view [\#74](https://github.com/GetBlimp/django-rest-framework-jwt/issues/74)

## [1.3.0](https://github.com/GetBlimp/django-rest-framework-jwt/tree/1.3.0) (2015-03-07)
[Full Changelog](https://github.com/GetBlimp/django-rest-framework-jwt/compare/1.2.0...1.3.0)

**Implemented enhancements:**

- Add docs using MkDocs [\#48](https://github.com/GetBlimp/django-rest-framework-jwt/issues/48)

**Closed issues:**

-  customize djangorestframework-jwt for authentication with email or username interchangeably  and password                               [\#84](https://github.com/GetBlimp/django-rest-framework-jwt/issues/84)
- Notes on  RSASSA-PKCS1-v1\_5 Should be Updates [\#82](https://github.com/GetBlimp/django-rest-framework-jwt/issues/82)
- Allow passing in an audience to verify\_signature. [\#81](https://github.com/GetBlimp/django-rest-framework-jwt/issues/81)
- Allow setting issuer [\#79](https://github.com/GetBlimp/django-rest-framework-jwt/issues/79)
- Documentation around Existing Session [\#78](https://github.com/GetBlimp/django-rest-framework-jwt/issues/78)

**Merged pull requests:**

- Update en\_US PO file [\#83](https://github.com/GetBlimp/django-rest-framework-jwt/pull/83) ([migonzalvar](https://github.com/migonzalvar))
- Allow subclassing JSONWebTokenAuthentication [\#80](https://github.com/GetBlimp/django-rest-framework-jwt/pull/80) ([cancan101](https://github.com/cancan101))
- Allow setting audience and issuer [\#77](https://github.com/GetBlimp/django-rest-framework-jwt/pull/77) ([cancan101](https://github.com/cancan101))
- Added a JWT verification view [\#75](https://github.com/GetBlimp/django-rest-framework-jwt/pull/75) ([Jwpe](https://github.com/Jwpe))
- Support HyperlinkedModelSerializer [\#73](https://github.com/GetBlimp/django-rest-framework-jwt/pull/73) ([semente](https://github.com/semente))
- Added JWT TestCase Class and Client [\#72](https://github.com/GetBlimp/django-rest-framework-jwt/pull/72) ([davideme](https://github.com/davideme))

## [1.2.0](https://github.com/GetBlimp/django-rest-framework-jwt/tree/1.2.0) (2015-01-24)
[Full Changelog](https://github.com/GetBlimp/django-rest-framework-jwt/compare/1.1.1...1.2.0)

**Fixed bugs:**

- DRF 3.0.1: ImportError:  ImportError: cannot import name smart\_text. [\#52](https://github.com/GetBlimp/django-rest-framework-jwt/issues/52)

**Closed issues:**

- Any chance you guys might port this to Falcon/Talons? [\#69](https://github.com/GetBlimp/django-rest-framework-jwt/issues/69)
- Encryption of user password in request [\#67](https://github.com/GetBlimp/django-rest-framework-jwt/issues/67)
- Query token `issue at`  [\#66](https://github.com/GetBlimp/django-rest-framework-jwt/issues/66)
- Multiple tokens and logout [\#64](https://github.com/GetBlimp/django-rest-framework-jwt/issues/64)
- Is the payload encrypted? [\#60](https://github.com/GetBlimp/django-rest-framework-jwt/issues/60)
- Generate token manually [\#58](https://github.com/GetBlimp/django-rest-framework-jwt/issues/58)
- Failure to import  [\#57](https://github.com/GetBlimp/django-rest-framework-jwt/issues/57)
- Automatically logged out when navigating directly to url [\#56](https://github.com/GetBlimp/django-rest-framework-jwt/issues/56)

**Merged pull requests:**

- user import problem for custom users issue fixed [\#70](https://github.com/GetBlimp/django-rest-framework-jwt/pull/70) ([cenkbircanoglu](https://github.com/cenkbircanoglu))
- Add translation utils [\#68](https://github.com/GetBlimp/django-rest-framework-jwt/pull/68) ([migonzalvar](https://github.com/migonzalvar))
- Added jwt\_response\_payload\_handler which allows returning additional response data [\#62](https://github.com/GetBlimp/django-rest-framework-jwt/pull/62) ([erichonkanen](https://github.com/erichonkanen))
- Changed potentially misleading error message [\#59](https://github.com/GetBlimp/django-rest-framework-jwt/pull/59) ([skolsuper](https://github.com/skolsuper))

## [1.1.1](https://github.com/GetBlimp/django-rest-framework-jwt/tree/1.1.1) (2014-12-11)
[Full Changelog](https://github.com/GetBlimp/django-rest-framework-jwt/compare/1.1.0...1.1.1)

**Closed issues:**

- Access user id and add to session with Ember [\#50](https://github.com/GetBlimp/django-rest-framework-jwt/issues/50)
- Unix Time Stamp [\#49](https://github.com/GetBlimp/django-rest-framework-jwt/issues/49)
- request.user shows AnonymousUser in middleware [\#45](https://github.com/GetBlimp/django-rest-framework-jwt/issues/45)

## [1.1.0](https://github.com/GetBlimp/django-rest-framework-jwt/tree/1.1.0) (2014-12-03)
[Full Changelog](https://github.com/GetBlimp/django-rest-framework-jwt/compare/1.0.2...1.1.0)

**Closed issues:**

- Not compatible with pyjwt 0.3 because decode method signature has changed. [\#40](https://github.com/GetBlimp/django-rest-framework-jwt/issues/40)

**Merged pull requests:**

- Add DRF 3.x compatibility [\#47](https://github.com/GetBlimp/django-rest-framework-jwt/pull/47) ([astagi](https://github.com/astagi))
- Invalid payload only if user\_id is None [\#46](https://github.com/GetBlimp/django-rest-framework-jwt/pull/46) ([astagi](https://github.com/astagi))

## [1.0.2](https://github.com/GetBlimp/django-rest-framework-jwt/tree/1.0.2) (2014-10-22)
[Full Changelog](https://github.com/GetBlimp/django-rest-framework-jwt/compare/1.0.1...1.0.2)

**Fixed bugs:**

- I have found a bug that passing username "0" and password "0" successfully receives a token [\#33](https://github.com/GetBlimp/django-rest-framework-jwt/issues/33)

**Closed issues:**

- request.user returns AnonymousUser [\#35](https://github.com/GetBlimp/django-rest-framework-jwt/issues/35)
- Multiple APIs and SSO using JWT [\#10](https://github.com/GetBlimp/django-rest-framework-jwt/issues/10)

**Merged pull requests:**

- update jwt\_decode\_handler to match pyjwt decode signature [\#41](https://github.com/GetBlimp/django-rest-framework-jwt/pull/41) ([vforgione](https://github.com/vforgione))

## [1.0.1](https://github.com/GetBlimp/django-rest-framework-jwt/tree/1.0.1) (2014-09-03)
[Full Changelog](https://github.com/GetBlimp/django-rest-framework-jwt/compare/1.0.0...1.0.1)

**Implemented enhancements:**

- Implement configurable Authorization header prefix [\#32](https://github.com/GetBlimp/django-rest-framework-jwt/issues/32)

**Closed issues:**

- Ability to refresh JWT token [\#15](https://github.com/GetBlimp/django-rest-framework-jwt/issues/15)

## [1.0.0](https://github.com/GetBlimp/django-rest-framework-jwt/tree/1.0.0) (2014-08-30)
[Full Changelog](https://github.com/GetBlimp/django-rest-framework-jwt/compare/0.1.6...1.0.0)

**Closed issues:**

- Is JWT in Authorization header a standard?  [\#31](https://github.com/GetBlimp/django-rest-framework-jwt/issues/31)
- RevokeJSONWebToken\(APIView\): [\#30](https://github.com/GetBlimp/django-rest-framework-jwt/issues/30)
- "Invalid payload" error if user\_id is 0 [\#28](https://github.com/GetBlimp/django-rest-framework-jwt/issues/28)
- Calling get token endpoint with expired token in header [\#27](https://github.com/GetBlimp/django-rest-framework-jwt/issues/27)
- User ID in payload [\#25](https://github.com/GetBlimp/django-rest-framework-jwt/issues/25)
- python-social-auth integration? [\#24](https://github.com/GetBlimp/django-rest-framework-jwt/issues/24)

## [0.1.6](https://github.com/GetBlimp/django-rest-framework-jwt/tree/0.1.6) (2014-07-30)
[Full Changelog](https://github.com/GetBlimp/django-rest-framework-jwt/compare/0.1.5...0.1.6)

**Closed issues:**

- Is it possible to use this to verify JWT without users? [\#22](https://github.com/GetBlimp/django-rest-framework-jwt/issues/22)
- unexpected keyword argument 'write\_only' [\#19](https://github.com/GetBlimp/django-rest-framework-jwt/issues/19)

**Merged pull requests:**

- User ID property in payloads \(and tests\) [\#26](https://github.com/GetBlimp/django-rest-framework-jwt/pull/26) ([orporat](https://github.com/orporat))
- Custom User Models + Tests [\#21](https://github.com/GetBlimp/django-rest-framework-jwt/pull/21) ([alvinchow86](https://github.com/alvinchow86))

## [0.1.5](https://github.com/GetBlimp/django-rest-framework-jwt/tree/0.1.5) (2014-05-27)
[Full Changelog](https://github.com/GetBlimp/django-rest-framework-jwt/compare/0.1.4...0.1.5)

**Closed issues:**

- Why jwt.py included in Pypi package ? [\#16](https://github.com/GetBlimp/django-rest-framework-jwt/issues/16)

**Merged pull requests:**

- Bump django-rest-framework dependency to 2.3.11 [\#20](https://github.com/GetBlimp/django-rest-framework-jwt/pull/20) ([stanhu](https://github.com/stanhu))
- Support Custom User models. [\#18](https://github.com/GetBlimp/django-rest-framework-jwt/pull/18) ([cborgolte](https://github.com/cborgolte))
- Clarified auth token request content type [\#14](https://github.com/GetBlimp/django-rest-framework-jwt/pull/14) ([arnuschky](https://github.com/arnuschky))

## [0.1.4](https://github.com/GetBlimp/django-rest-framework-jwt/tree/0.1.4) (2014-03-13)
[Full Changelog](https://github.com/GetBlimp/django-rest-framework-jwt/compare/0.1.2...0.1.4)

**Closed issues:**

- Username and password encoding on login [\#13](https://github.com/GetBlimp/django-rest-framework-jwt/issues/13)
- Wrong behavior if a field is empty [\#11](https://github.com/GetBlimp/django-rest-framework-jwt/issues/11)
- Cannot use JSONWebTokenAuthentication and OAuth2Authentication authentication classes at the same time [\#3](https://github.com/GetBlimp/django-rest-framework-jwt/issues/3)
- Overriding JSONWebTokenSerializer.validate\(\) to auth based on 3rd party response and not user model? [\#2](https://github.com/GetBlimp/django-rest-framework-jwt/issues/2)

**Merged pull requests:**

- Fix issue \#11: Allow null e-mail addresses [\#12](https://github.com/GetBlimp/django-rest-framework-jwt/pull/12) ([stanhu](https://github.com/stanhu))
- Custom User model compatibility [\#9](https://github.com/GetBlimp/django-rest-framework-jwt/pull/9) ([spenthil](https://github.com/spenthil))
- fix\(docs\): fix Keys name of `JWT\_AUTH` [\#8](https://github.com/GetBlimp/django-rest-framework-jwt/pull/8) ([theskumar](https://github.com/theskumar))
- Handle missing fields in JWT payload [\#7](https://github.com/GetBlimp/django-rest-framework-jwt/pull/7) ([stanhu](https://github.com/stanhu))
- Fix missing comma in documentation [\#6](https://github.com/GetBlimp/django-rest-framework-jwt/pull/6) ([stanhu](https://github.com/stanhu))

## [0.1.2](https://github.com/GetBlimp/django-rest-framework-jwt/tree/0.1.2) (2014-01-23)
[Full Changelog](https://github.com/GetBlimp/django-rest-framework-jwt/compare/0.1.1...0.1.2)

**Merged pull requests:**

- Adds curl command with auth headers [\#5](https://github.com/GetBlimp/django-rest-framework-jwt/pull/5) ([gcollazo](https://github.com/gcollazo))
- Added tests to validate JWT Auth compatibility with OAuth2 [\#4](https://github.com/GetBlimp/django-rest-framework-jwt/pull/4) ([marccerrato](https://github.com/marccerrato))

## [0.1.1](https://github.com/GetBlimp/django-rest-framework-jwt/tree/0.1.1) (2014-01-20)
[Full Changelog](https://github.com/GetBlimp/django-rest-framework-jwt/compare/0.1.0...0.1.1)

**Merged pull requests:**

- Support custom user models in Django \>= 1.5 [\#1](https://github.com/GetBlimp/django-rest-framework-jwt/pull/1) ([rivol](https://github.com/rivol))

## [0.1.0](https://github.com/GetBlimp/django-rest-framework-jwt/tree/0.1.0) (2014-01-16)


\* *This Change Log was automatically generated by [github_changelog_generator](https://github.com/skywinder/Github-Changelog-Generator)*