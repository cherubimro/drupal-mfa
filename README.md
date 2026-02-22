# WebAuthn/TOTP Multi-Factor Authentication for Drupal 9

A Drupal 9 module providing FIDO2/WebAuthn security key and TOTP authenticator
app support for two-factor (2FA) and multi-factor (MFA) authentication.

## Features

- **WebAuthn/FIDO2** — hardware security keys, platform authenticators, passkeys
- **TOTP** — authenticator apps (Google Authenticator, andOTP, FreeOTP, Aegis, etc.)
- **MFA mode** — require both methods when both are configured
- **2FA mode** — any single method suffices
- Per-user 2FA toggle with admin policy override (optional/required)
- 2FA gate via event subscriber — users are jailed to the verification page until all required factors are verified
- User self-service key management at `/user/{uid}/security-keys`
- Admin configuration at `/admin/config/people/webauthn`
- Clone detection for WebAuthn credentials (sign counter anomaly)
- Drupal 10/11 forward-compatible (`once()` API)

## Requirements

- Drupal 9.2+ (compatible with 10/11)
- PHP 7.4+
- HTTPS (required by WebAuthn browser API)

## Installation

```bash
cd modules/webauthn
composer install
```

Enable the module via Drush or the admin UI:

```bash
drush en webauthn
```

## Configuration

1. Go to `/admin/config/people/webauthn`
2. Set **Relying Party ID** — your domain (e.g. `example.com`). Must match the
   domain users access the site from.
3. Set **Relying Party Name** — displayed in authenticator prompts
4. Choose **Policy**:
   - `optional` — users choose whether to enable 2FA
   - `required` — all users must set up at least one 2FA method
5. Choose **Verification Mode**:
   - `any` — any single configured method clears the gate (2FA)
   - `all` — every configured method must be verified (MFA)

## Architecture

### Login flow

1. User submits username/password at `/user/login`
2. `hook_form_user_login_form_alter()` replaces the submit handler
3. Custom handler checks policy and user 2FA configuration
4. If 2FA required: authenticates the user, sets `webauthn_2fa_pending` in
   session, redirects to `/user/webauthn-verify`
5. `WebAuthn2faSubscriber` (priority 30) blocks all routes except verify,
   AJAX endpoints, and logout while the flag is set
6. Verification page presents configured methods (WebAuthn, TOTP, or both)
7. On successful verification, the session flag is cleared and the user is
   redirected to their original destination

### MFA step tracking

In `all` mode, `complete2fa()` tracks completed methods in
`webauthn_mfa_completed` session array. Each verification returns a partial
response until all configured methods are verified. The JS handles step
transitions and progress indicators.

### Services

| Service | Class | Purpose |
|---------|-------|---------|
| `webauthn.manager` | `WebAuthnManager` | FIDO2 ceremony logic, credential DB ops |
| `webauthn.totp_manager` | `TotpManager` | TOTP secret management, QR codes, verification |
| `webauthn.2fa_subscriber` | `WebAuthn2faSubscriber` | Request gate during pending 2FA |

### Database

- `webauthn_credentials` — stores WebAuthn credential public keys, metadata
- `users_data` (Drupal core) — stores per-user TOTP secrets and 2FA enabled flag

## Libraries

| Library | License | Purpose |
|---------|---------|---------|
| [lbuchs/webauthn](https://github.com/nicoswd/webauthn) v2.2 | MIT | FIDO2/WebAuthn ceremony logic |
| [spomky-labs/otphp](https://github.com/Spomky-Labs/otphp) v10.x | MIT | TOTP generation and verification |
| [chillerlan/php-qrcode](https://github.com/chillerlan/php-qrcode) v5.x | MIT / Apache-2.0 | QR code rendering (inline SVG) |

## File structure

```
├── composer.json / composer.lock
├── config/
│   ├── install/webauthn.settings.yml
│   └── schema/webauthn.schema.yml
├── css/webauthn.css
├── js/webauthn.js
├── src/
│   ├── Controller/
│   │   ├── WebAuthnController.php        # AJAX endpoints
│   │   └── WebAuthnUserSettingsController.php
│   ├── EventSubscriber/
│   │   └── WebAuthn2faSubscriber.php     # 2FA gate
│   ├── Form/
│   │   ├── WebAuthnAdminSettingsForm.php
│   │   └── WebAuthnVerifyForm.php
│   └── Service/
│       ├── TotpManager.php
│       └── WebAuthnManager.php
├── templates/
│   ├── webauthn-user-settings.html.twig
│   └── webauthn-verify.html.twig
├── webauthn.info.yml
├── webauthn.install
├── webauthn.libraries.yml
├── webauthn.links.menu.yml
├── webauthn.links.task.yml
├── webauthn.module
├── webauthn.permissions.yml
├── webauthn.routing.yml
└── webauthn.services.yml
```

## Permissions

- `administer webauthn` — access admin settings page
- `manage own security keys` — register/delete keys, configure TOTP, toggle 2FA

## License

GPL-2.0-or-later
