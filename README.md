# LimeSurveyWebhook (Cockpit fork)

Sends one signed webhook to the Cockpit when a survey is completed
(`afterSurveyComplete`). The Cockpit then fetches the answers itself through
RemoteControl, so this plugin never transmits answers.

Fork of [IrishWolf/LimeSurveyWebhook](https://github.com/IrishWolf/LimeSurveyWebhook),
hardened for Cockpit spec 014 (see `docs/entscheidungen/0004-befragungen.md` in the
Cockpit repository).

## What changed compared to upstream

| Upstream | This fork |
| --- | --- |
| `CURLOPT_SSL_VERIFYPEER = false` | TLS verification on, HTTPS only |
| Token in plaintext, no signature | HMAC-SHA256 over `<timestamp>.<body>`, timestamp header, 5 s window in the Cockpit |
| Full response in body and log | Only `surveyId`, `responseId`, `token`; the log gets the outcome only |
| Debug mode shows the token to respondents | Debug removed |
| `token` always `null` | Participant token read from the response table |
| No timeout, no error handling | 5 s connect/read timeout, failures logged without data |
| `multipart/form-data` | JSON |

## Request

```
POST https://<cockpit-domain>/api/webhooks/limesurvey
Content-Type: application/json
X-Cockpit-Timestamp: <unix seconds>
X-Cockpit-Signature: sha256=<hex>

{"surveyId":901,"responseId":"42","token":"<participant token>"}
```

`X-Cockpit-Signature` is `HMAC-SHA256(secret, "<timestamp>.<raw body>")`. The Cockpit
rejects timestamps older than 5 minutes, unknown signatures and bodies larger than
8 KiB, and ignores a repeated delivery for 15 minutes.

## Install

1. Zip `config.xml`, `LimeSurveyWebhook.php` and `src/` (the folder `src` must stay a
   subfolder) and upload it under **Configuration → Plugins → Upload plugin**.
2. Open the plugin settings and set:
   - **Webhook URL**: `https://<cockpit-domain>/api/webhooks/limesurvey`
   - **Survey IDs**: comma-separated template survey ids (empty = every survey)
   - **Webhook secret**: same value as `LIMESURVEY_WEBHOOK_SECRET` in the Cockpit
3. Activate the plugin.

The Cockpit keeps `LIMESURVEY_WEBHOOK_SECRET` empty by default; with no secret the
route answers 404 and this plugin should not be activated.

## Test

```sh
php tests/webhook-payload.test.php
```

Covers the body shape (no answers), the signature construction and the headers that
`src/server/surveys/webhook.ts` verifies.

## License

GPL-3.0-or-later, see [LICENSE](LICENSE).
