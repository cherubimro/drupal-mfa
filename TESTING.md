# Testing the 1.0.2 fixes

Written for anyone retesting the reported issue and the two further ones. Every
step below was run against the branch; where a result differs from the released
code, both are given.

Lab used here: Drupal 11.3.2, PHP 8.3, SQLite, `basic_auth` and `jsonapi`
enabled, a test user with a known password, a TOTP secret enrolled and the
module's policy set to `required`.

Two things to know before starting:

- **On 1.0.1 the module raises a fatal error when loaded**, so to test the
  released behaviour you must first remove the typed redeclarations of
  `$configFactory` and `$requestStack` from `src/Form/WebAuthnVerifyForm.php`
  and `src/Controller/WebAuthnUserSettingsController.php`. 1.0.0 does not need
  this.
- **On database drivers that return a user ID as a string, such as SQLite,
  logging in through the login form ends in a 500** on both released versions.
  MySQL returns an integer and is unaffected. If you are on SQLite and want to
  reach the released behaviour through the form, cast the value in
  `webauthn_user_login_submit()`.

## 1. The reported issue: no attempt limiting

Log in with the password, stop at the verification page, and submit wrong codes
to `/webauthn/totp-verify` with the session cookie and the token from that page.

- **Released:** every attempt returns `400 {"success":false,"error":"Invalid
  code. Please try again."}`, indefinitely.
- **Fixed:** attempts 1–5 return 400; the 6th and later return
  `429 {"success":false,"error":"Too many attempts. Please try again later."}`
  with `Retry-After: 900`. A correct code is also refused while locked. The
  limits are 5 per 15 minutes and 20 per 24 hours, per account.

Two details worth checking:

- **Refused attempts must not extend the lockout.** Keep sending requests after
  the 429 and confirm the lock still expires 15 minutes after the last *counted*
  attempt, not after the last request.
- **A code cannot be reused.** Submit a correct code, then submit the same code
  again in a later login; the second use is rejected.

## 2. The window size

With the released `spomky-labs/otphp: ^10.0`, `verify($code, NULL, 10)` counts
±10 thirty-second steps, so about 21 codes are valid at once. To see it:

```php
$totp = OTPHP\TOTP::createFromSecret('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP');
$t = 1791000015;
for ($k = -12; $k <= 12; $k++) {
  printf("step %+3d %s\n", $k, $totp->verify($totp->at($t + $k * 30), $t, 10) ? 'accepted' : 'rejected');
}
```

- **Released (otphp 10.x):** steps −10 to +10 accepted, 21 in total. Trying all
  1,000,000 six-digit codes at a fixed instant accepts exactly 21.
- **Fixed (otphp 11.4.3+, leeway 15 seconds):** at most two codes at any moment.

## 3. The enforcement gap

This is the one that needs no guessing. With the policy set to `required` and a
user who has a second factor enrolled:

```sh
# Core's own JSON login endpoint — no extra modules needed.
curl -s -c jar -H 'Content-Type: application/json' \
  -d '{"name":"USER","pass":"PASSWORD"}' \
  'http://SITE/user/login?_format=json'

curl -s -b jar -o /dev/null -w '%{http_code}\n' http://SITE/user/N/edit
curl -s -b jar http://SITE/jsonapi/user/user/UUID | grep -o '"mail":"[^"]*"'
```

- **Released:** the login returns 200 with a full session, `/user/N/edit` returns
  200, and JSON:API returns the account's private fields. No code was ever
  requested.
- **Fixed:** `/user/N/edit` returns 302 to the verification page, and the
  JSON:API request returns 403 with
  `{"verification_required":true,"verify_url":"/webauthn/api/totp-verify"}`.

HTTP Basic behaves the same way; substitute `-u USER:PASSWORD` for the cookie.

Also worth checking on the fixed branch:

- A request that cannot complete the ceremony gets an **unthemed** 403: short
  HTML with no blocks and no toolbar, so nothing renders as the account.
- A 404 or 403 for a session that still owes a factor redirects to verification
  rather than rendering the error page in that user's context.
- Blocks and the toolbar are absent on the verification page.
- Server errors are **not** swallowed: they still produce a 500 and are logged.

## 4. The redirect

```sh
# Follow the login with an attacker-chosen destination.
http://SITE/user/login?destination=https%3A%2F%2Fexample.com
http://SITE/user/login?destination=javascript%3Aalert(1)
```

Complete the login and verification, then see where the browser goes.

- **Released:** the JSON response's `redirect` is the supplied value, and the
  module's JavaScript follows it with `window.location.href` — so an external
  site, or a `javascript:` URL executing in the site's context.
- **Fixed:** both are discarded and the user lands on their account page. The
  validation accepts only paths beginning with a single `/`, with no control
  characters, that core does not consider external. `//host`, `/\host`,
  `/<tab>/host`, `data:` and scheme URLs are all rejected.

Note for anyone writing a similar check: `UrlHelper::isExternal()` does **not**
report `javascript:` as external, so testing only for external URLs does not
catch this.

## 5. Verifying without a browser

The fixed branch adds `/webauthn/api/totp-verify` for clients that cannot render
the verification page:

```sh
# The JSON login response already contains the csrf_token this needs.
TOKEN=$(curl -s -c jar -H 'Content-Type: application/json' \
  -d '{"name":"USER","pass":"PASSWORD"}' \
  'http://SITE/user/login?_format=json' | jq -r .csrf_token)

curl -s -b jar -X POST -H "X-CSRF-Token: $TOKEN" \
  -H 'Content-Type: application/json' -d '{"code":"123456"}' \
  http://SITE/webauthn/api/totp-verify
```

Wrong code gives 400, correct gives 200, and the attempt limit applies here too
since it is the same controller. Security keys cannot be used this way; WebAuthn
needs a browser.

## 6. Security keys

Worth confirming independently of the above, since the shared completion code
changed.

If you have hardware keys, register one and log in with it. If not, Chrome's
virtual authenticator works: enable the `WebAuthn` domain over the DevTools
protocol, call `WebAuthn.addVirtualAuthenticator` with `protocol: ctap2`,
`hasUserVerification: true` and `isUserVerified: true`, then drive the pages
normally.

Two checks matter:

- **Which method completed the login.** The fixed branch logs it; look for
  `Two-factor verification completed for user N (webauthn)` and confirm the
  credential's `last_used` and `sign_count` advanced.
- **Keys registered before the update still work.** Register a key on the
  released code, update the module without touching the database, then log in
  with that same key. It should succeed: the credentials table, the signature
  verification, the `lbuchs/webauthn` library and the relying party identifier
  are all unchanged.

## 7. Requiring every configured factor

Set `verification_mode` to `all` for an account that has both a security key and
an authenticator app. Neither factor alone may finish the login.

Tested here with Chrome's virtual authenticator on Drupal 11.3.2:

- Password accepted, user sent to the verification page.
- The key ceremony completes. The session stays on the verification page, the
  key section is hidden and the code section is shown. **One factor is not
  enough**, which is the point of the mode.
- The code is accepted, and the login completes; the account edit page is then
  reachable.

One observation rather than a fault: only the **final** factor appears in the
log, because completion is logged once the login finishes, while the first
factor returns earlier as partial progress. So a log for an "all" mode login
reads `(totp)` even though a key was also presented. Recording both would be
better for incident response and is worth a later, non-security release.

## 8. Things the fix deliberately stops

Each of these worked only while the second factor was being skipped, so they are
expected to fail now. They are not regressions:

- API or script access using a user's password, for an account with a second
  factor, now returns 403.
- SSO modules that log a user in without the login form now send that user to
  verification afterwards.
- Masquerading into an account with a second factor leaves the administrator on
  that account's verification page; log out to recover.
- A user already signed in when the module is updated is asked to verify once.

## 9. What has not been tested

Being explicit so nobody assumes more coverage than exists:

- PHP 8.1. The branch declares support for it and nobody has run it there.
- MySQL. The user-ID fix makes the code independent of what the driver returns,
  but the branch has only been exercised on SQLite.
- Masquerade and specific SSO modules, which are documented above rather than
  handled.
- There are no automated tests in the module yet.
