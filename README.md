# mod_auth_oauth

*This module is unmaintained, so it's up for grab. Have a fork that is maintained ? Telle me in some issue and i'll redirect to it, or I can trensfer this one.*

An authentication module for Prosody using a OAuth 2.0 backend such as Keycloak, that supports `SASL OAUTHBEARER` and `PLAIN` mechanisms.

When `PLAIN` is used, the username and password are checked by retrieving a token using the `oauth_url_token` endpoint.

When `OAUTHBEARER` is used, the token is checked against the `oauth_url_userinfo` endpoint.

## Dependencies - Important

This module depends on `mod_sasl_oauthbearer` in which the `password = saslprep(password);` has been removed.

## Configuration

```
authentication = "oauth"

oauth_host = "keycloak.domain.tld"
oauth_url_token = "https://keycloak.domain.tld/auth/realms/master/protocol/openid-connect/token"
oauth_url_userinfo = "https://keycloak.domain.tld/auth/realms/master/protocol/openid-connect/userinfo"
oauth_client_id = "CLIENT_ID"
oauth_client_secret = "CLIENT_SECRET"
```
