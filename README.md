### Sample Litestar OKTA Python App ###
This is a bare bones example which implements OKTA to secure Litestar APIs.
See https://dev.to/pbaletkeman/secure-litestar-apis-with-okta-4b8-temp-slug-7126418 for a write up on this.


Run command:
litestar --app lite:app run

OpenAPI Sites:
- http://127.0.0.1:8000/schema/
  - default site (redoc implementation)
- http://127.0.0.1:8000/schema/swagger
  - swagger implementation
  - https://swagger.io/
- http://127.0.0.1:8000/schema/elments
  - spotlight elements implementation
  - https://stoplight.io/open-source/elements
- http://127.0.0.1:8000/schema/rapidoc
  - rapidoc implementation
  - https://rapidocweb.com/
- http://127.0.0.1:8000/schema/redoc
  - redoc implementation
  - https://redocly.com/
