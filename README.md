# authentik-alipay-kyc

Go + Vue middleware for launching Alipay real-name verification from an authentik application and writing the result back to authentik user attributes.

Flow:

1. User clicks the `实名认证` application in authentik.
2. This service authenticates the user through authentik OIDC.
3. The user enters name and ID card number, then the service initializes Alipay identity verification and redirects the browser to Alipay.
4. After Alipay returns, this service calls Alipay query API and only writes back when `passed == "T"`.
5. authentik receives a user attribute containing verification status data.

The ID number is not stored. The service keeps only an HMAC-SHA256 hash, ID last four characters, masked name with only the last character visible, channel, and verification time.

Verification counters are stored in a local JSON file and are not shown in the frontend. They can be read through an authenticated API.

## authentik Setup

Create an OAuth2/OpenID Provider and an Application named `实名认证`.

Provider settings:

- Redirect URI: `https://<kyc-service>/auth/callback`
- Launch URL: `https://<kyc-service>/`
- Scopes: `openid profile email`

Add a property mapping that exposes the authentik user primary key:

```python
return {
    "ak_user_id": str(request.user.pk),
}
```

Create an authentik API token with permission to view and change users. Set `AUTHENTIK_USER_ID_CLAIM=ak_user_id` unless you use a different claim name.

The service PATCHes:

```json
{
  "attributes": {
    "alipay_kyc": {
      "verified": true,
      "verified_at": "2026-06-21T09:00:00Z",
      "channel": "alipay",
      "id_hash": "hmac-sha256-hex",
      "id_last4": "1234",
      "name_masked": "*三"
    }
  }
}
```

## Alipay Setup

The service uses Alipay OpenAPI methods:

- `alipay.user.certify.open.initialize`
- `alipay.user.certify.open.certify`
- `alipay.user.certify.open.query`

Configure the Alipay application for identity verification and set the return URL to `https://<kyc-service>/verify/callback`. The service also sends a notify URL at `https://<kyc-service>/api/alipay/notify`, but the browser return path performs the authoritative query and authentik write-back.

## Configuration

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `HTTP_ADDR` | no | `:8080` | Listen address. |
| `PUBLIC_URL` | yes | empty | Public base URL of this service. |
| `SESSION_KEYS` | production | generated | Comma-separated base64 keys, at least 32 bytes each. Generate with `openssl rand -base64 64`. |
| `SESSION_SECURE` | no | derived | Secure cookie flag. Defaults to true for HTTPS `PUBLIC_URL`. |
| `HASH_PEPPER` | yes | empty | Secret HMAC key for ID hashes. |
| `STATS_FILE` | no | `/data/stats.json` | Local JSON file storing total, success, and failure counters. |
| `STATS_API_TOKEN` | yes | empty | Bearer token required for `GET /api/stats`. |
| `OIDC_ISSUER` | yes | empty | authentik provider issuer URL. Use the exact issuer from authentik discovery, usually ending with `/`, for example `https://auth.example.com/application/o/alipay-kyc/`. |
| `OIDC_CLIENT_ID` | yes | empty | OIDC client ID. |
| `OIDC_CLIENT_SECRET` | yes | empty | OIDC client secret. |
| `OIDC_REDIRECT_URL` | no | `${PUBLIC_URL}/auth/callback` | OIDC callback URL. |
| `AUTHENTIK_BASE_URL` | yes | empty | authentik base URL. |
| `AUTHENTIK_TOKEN` | yes | empty | authentik API token. |
| `AUTHENTIK_USER_ID_CLAIM` | no | `ak_user_id` | OIDC claim used as authentik user pk. |
| `AUTHENTIK_ATTRIBUTE_KEY` | no | `alipay_kyc` | User attribute key written by the service. |
| `ALIPAY_GATEWAY_URL` | no | `https://openapi.alipay.com/gateway.do` | Alipay OpenAPI gateway. |
| `ALIPAY_APP_ID` | yes | empty | Alipay app ID. |
| `ALIPAY_APP_PRIVATE_KEY` | yes | empty | RSA private key PEM, `\n` escapes are accepted. |
| `ALIPAY_PUBLIC_KEY` | yes | empty | Alipay public key PEM. |
| `ALIPAY_BIZ_CODE` | no | `FACE` | Alipay identity verification scene code. |
| `ALIPAY_CERT_TYPE` | no | `IDENTITY_CARD` | Alipay certificate type. |
| `ALIPAY_RETURN_URL` | no | `${PUBLIC_URL}/verify/callback` | Browser return URL. |
| `ALIPAY_CALLBACK_URL` | no | `${PUBLIC_URL}/api/alipay/notify` | Alipay notify URL. |

## Run

```bash
npm ci
npm run build
go test ./...
go run ./cmd/alipay-kyc
```

Docker:

```bash
docker compose up --build
```

`docker-compose.yml` uses a named volume for `/data` so the local stats file survives container rebuilds. If you replace it with a bind mount such as `./data:/data`, make sure the directory is writable by container UID `65532`.

Stats API:

```bash
curl -H "Authorization: Bearer $STATS_API_TOKEN" \
  https://<kyc-service>/api/stats
```

Example response:

```json
{
  "total": 12,
  "success": 10,
  "failure": 2,
  "updated_at": "2026-06-22T09:00:00Z"
}
```

## GHCR

`.github/workflows/docker.yml` builds and tests the app, then publishes multi-arch images to `ghcr.io/<owner>/<repo>` on branch and tag pushes. Pull requests build without pushing.

## References

- Authentik API: `PATCH /api/v3/core/users/{id}/` for updating user `attributes`: <https://api.goauthentik.io/reference/core-users-partial-update/>
- Alipay identity verification product/API documentation: <https://opendocs.alipay.com/open/009yj1?pathHash=6cff73be>
