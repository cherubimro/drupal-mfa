# dmfa 1.0.2 — security release

**Everyone running 1.0.0 or 1.0.1 should update.** This release fixes three
security issues and a fatal error that prevented 1.0.1 from loading at all.

Read the "Changes that may break your site" section before updating: closing
the second of the three issues necessarily stops several things that only
worked because two-factor authentication was being skipped.

## Security fixes

**Two-factor authentication was not enforced for every login.** The module only
marked a login as needing a second factor when the user signed in through the
HTML login form. Any other way of logging in was never challenged — including
Drupal core's own JSON login endpoint, which needs no extra modules, and
methods that present credentials on every request such as HTTP Basic. Anyone
who knew a password could obtain a fully authenticated session as that account
without ever being asked for a code. The requirement is now enforced for every
request: a session is accepted only once it has completed verification, and a
request that cannot complete the verification is refused.

**Authenticator codes could be guessed without limit.** Nothing counted failed
attempts at `/webauthn/totp-verify`, and the accepted time window was five
minutes wide in each direction, so roughly 21 different codes were valid at any
moment. Someone who already had the password could try codes at full request
speed. Failed attempts are now limited per account (5 per 15 minutes and 20 per
24 hours), the window accepts at most two codes, and a code cannot be used
twice.

**A crafted login link could run script on your site after a successful
login.** The page shown after verification was taken from the login URL's
`destination` parameter and followed by JavaScript, which bypasses Drupal's own
redirect checks. Drupal removes destinations it considers external, so this
could not send a user to a different site — but it does not treat `javascript:`
as external, so a link carrying one reached the module and ran in your site's
context immediately after the user signed in. `data:` destinations passed
Drupal's filter in the same way, but current browsers refuse to navigate to
them, so those were inert. Destinations are now accepted only if they are paths
on this site. This affected 1.0.0; on
1.0.1 the login form fails earlier, so it could not be reached.

## Fatal error on 1.0.1

Since 1.0.1 the module raised `Type of ...::$requestStack must not be defined`
when loaded, on every supported Drupal version, because it redeclared two
properties that Drupal core declares without a type. The verification page and
the security-keys page were unreachable, so users who needed a second factor
could not finish signing in and nobody could enrol. This is fixed.

Reported by nicrodgers, tested by vinodhini.e, reviewed by florent jousseaume
(issue 3582203).

A second fatal error is also fixed: on database drivers that return a user ID as
a string rather than an integer, logging in through the login form ended in a 500
before the second factor was considered. SQLite is affected; MySQL is not,
because it returns an integer, which is why this was not noticed earlier. Both
1.0.0 and 1.0.1 are affected.

## Your existing security keys and authenticator apps keep working

Nothing stored for your users changes. Registered security keys continue to
authenticate after the update, and so do authenticator apps.

This was tested rather than assumed: a key was registered while 1.0.1 was
installed, the module was then updated without touching the database, and the
same key completed a login afterwards — the credential's "last used" timestamp
and signature counter both advanced, and the log recorded the security key as
the method that satisfied verification.

The parts that make keys work are untouched by this release: the credentials
table, the signature verification, the `lbuchs/webauthn` library and the relying
party identifier. That last one matters most — an authenticator ties each
credential to a specific domain, so a change there would have invalidated every
registered key. The move to a newer OTP library affects authenticator app codes
only.

One thing to expect: anyone who is **already signed in** when you update is
asked to verify once, because their session has not yet recorded that it passed
a second factor. This is deliberate, and signing in again is all it takes.

## Changes that may break your site

All four of these worked only because the second factor was being skipped.
Closing that gap stops them. This is intended, but check whether any applies to
you before updating.

- **API access with a password.** Scripts or integrations that call JSON:API,
  REST or any route using HTTP Basic credentials for an account that has 2FA
  enabled now receive `403`. Such a request cannot present a second factor, so
  it is refused. Use an account without 2FA for machine access, or an
  authentication method that does not rely on the user's password.
- **Single sign-on modules.** CAS, SAML, OpenID Connect, social login and
  similar modules log the user in without the login form. Those users are now
  sent to the verification page afterwards, where before they were let straight
  through.
- **Masquerade and similar switch-user modules.** Taking over an account that
  has 2FA enabled now lands the administrator on that account's verification
  page, which they cannot complete. Log out to recover. Avoid masquerading into
  2FA accounts for now.
- **Decoupled front ends.** Clients that sign in through
  `/user/login?_format=json` are now held at verification instead of being
  logged in. They can complete it — see "Verifying without a browser" below —
  but they have to be changed to do so, where previously they were let through
  with no second factor at all.

Per-provider exemptions, so that a chosen authentication method can be allowed
through deliberately, are planned for a later, non-security release.

## Verifying without a browser

An application or decoupled front end whose users have an authenticator app can
now complete verification over JSON:

1. Sign in as usual at `/user/login?_format=json`. The response already contains
   a `csrf_token`, which is the `X-CSRF-Token` value needed below.
2. Any further request is answered with `403` and a body naming what is
   outstanding, for example:

   ```json
   {
     "message": "Two-factor verification is required before this request can be completed.",
     "verification_required": true,
     "verify_url": "/webauthn/api/totp-verify"
   }
   ```

3. Submit the six-digit code to that URL:

   ```
   POST /webauthn/api/totp-verify
   X-CSRF-Token: <the csrf_token from step 1>
   Content-Type: application/json

   {"code": "123456"}
   ```

   The reply is `200` on success, `400` for a wrong code and `429` once the
   attempt limit is reached, exactly as for the browser.

Note that the session identifier is regenerated when verification succeeds, so
the token from step 1 is no longer valid afterwards. A client that needs one for
later requests should fetch a fresh token from `/session/token`.

This route uses the same verification code as the browser, so the attempt limit,
the replay check and the code format requirement all apply to it as well.
Security keys cannot be used this way: WebAuthn needs a browser.

## Requirements

- **PHP 8.1 or later** (was 7.4).
- **Drupal 10 or 11** (was 9.2 or later). Drupal 9 is end of life and the OTP
  library now requires PHP 8.1.
- **`spomky-labs/otphp` 11.4.3 or later** (was 10.x). Composer refuses to
  install the 10.x series because of two published advisories against it, so
  1.0.1 could not be installed as released. Run `composer update` when
  updating.

## Other changes

- The previous login time and IP address are shown after verification succeeds,
  rather than on the page that asks for the code.
- Failed verification attempts, and each lockout, are written to the log.
- The session identifier is regenerated when verification completes.
- While verification is pending, blocks and the toolbar are hidden and pages
  are not served from the dynamic page cache, so no account-specific content is
  rendered before the second factor is provided.

## If a user is locked out

A user who loses their authenticator has no self-service recovery in this
release. An administrator can clear a lockout or remove the enrolled factor
with Drush:

```sh
# Clear a verification lockout for user 7.
drush php:eval '\Drupal::service("flood")->clear("webauthn.totp_verify", "uid:7");'

# Remove the authenticator app for user 7, so they can enrol again.
drush php:eval '\Drupal::service("user.data")->delete("webauthn", 7, "totp_secret");'

# Remove all of user 7's registered security keys.
drush sql:query "DELETE FROM webauthn_credentials WHERE uid = 7"
```

Under the "required" policy, removing a user's last factor also removes the
requirement for that user until they enrol again.

## Credits

- **Sanjeev Kumar** (ksanjeev284) reported the missing rate limit on
  authenticator code verification, with a clear write-up and a reproducible
  method. The two further security issues above were found while reviewing the
  module for similar problems, which that report prompted, so they are his doing
  as much as mine. He also retested the fix thoroughly and found one more case
  that is fixed here, where an error page for a request that could not supply a
  second factor was still rendered in the account's context.
- **nicrodgers** reported the fatal error on load and opened a merge request for
  it.
- **vinodhini.e** tested and confirmed that fix.
- **florent jousseaume** reviewed it and suggested the better approach: removing
  the typed redeclarations rather than making them untyped, so the properties
  follow whatever Drupal core declares.
