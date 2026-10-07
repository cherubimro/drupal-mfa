# Changelog

## 1.0.2 — security release

Fixes three security issues and a fatal error that prevented 1.0.1 from loading.
See `RELEASE-NOTES-1.0.2.md` for the full notes, including four behaviours that
stop working because they depended on the second factor being skipped.

### Security

- **Two-factor authentication was not enforced for every login.** The module
  marked a login as needing a second factor only in the login form's submit
  handler, and the gate let a request through whenever that marker was absent.
  Any login that did not go through the form therefore skipped verification
  entirely — including Drupal core's own JSON login endpoint, which is available
  with no additional modules. A second factor is now required for every request:
  a session passes only once it has completed verification, and a request that
  cannot complete the ceremony is refused with an unthemed response.
- **Authenticator codes could be guessed without limit.** Failed attempts at
  `/webauthn/totp-verify` were not counted, and the accepted window was five
  minutes wide in each direction, so about 21 codes were valid at any moment.
  Attempts are now limited per account (5 per 15 minutes, 20 per 24 hours), the
  window accepts at most two codes, and a code cannot be used twice.
- **The page shown after verification could be chosen by an attacker.** The
  destination came from the login URL and was followed by JavaScript, which
  bypasses Drupal's redirect protection, so a crafted login link could send the
  user to another site or run a `javascript:` URL. Destinations are now accepted
  only if they are local paths.

### Fixed

- Fatal error on load since 1.0.1 (`Type of ...::$requestStack must not be
  defined`), caused by redeclaring with types two properties that Drupal core
  declares untyped. The verification page and the security-keys page were
  unreachable on every supported core version.
- A fatal error when logging in through the login form, on database drivers
  where a user ID is returned as a string rather than an integer. The login
  submit handler passed that value to a method typed for `int` under
  `strict_types`, so the request ended in a 500 before any second factor was
  considered. Reproduced on SQLite; MySQL returns an integer, so sites on MySQL
  were unaffected, which is why this went unnoticed. Present in 1.0.0 and
  1.0.1.
- Error pages, blocks and the toolbar are no longer rendered in the user's
  context while verification is pending, and such pages are not served from the
  dynamic page cache.
- The session identifier is regenerated when verification completes.
- The previous login time and IP are shown after verification rather than
  before it.

### Added

- `/webauthn/api/totp-verify`, so an application or decoupled front end can
  complete verification using the `X-CSRF-Token` header rather than a token
  issued by the HTML page. It shares the browser's controller, so the attempt
  limit, replay check and code format requirement all apply. Security keys still
  need a browser.
- Failed verification attempts and lockouts are written to the log.

### Changed

- Requires PHP 8.1 or later (was 7.4) and Drupal 10 or 11 (was 9.2 or later).
- Requires `spomky-labs/otphp` 11.4.3 or later (was 10.x). Composer refuses the
  10.x series because of two published advisories against it, so 1.0.1 could not
  be installed as released.

### Credits

- **Sanjeev Kumar** (ksanjeev284) — reported the missing rate limit on
  authenticator code verification, with a clear write-up and a reproducible
  method. The other two security issues were found while reviewing the module
  for similar problems, which that report prompted.
- **nicrodgers** — reported the fatal error on load and opened the merge request
  for it.
- **vinodhini.e** — tested and confirmed the fix for the fatal error.
- **florent jousseaume** — reviewed that fix and suggested the better approach:
  removing the redeclarations rather than making them untyped, so the properties
  track whatever core declares.

### A note on the underlying cause

Two of the three security issues above are not really specific to this module.
Drupal core has no state for "the password was correct but this login is not
finished yet": a successful password check writes the user's id into the session
immediately. Every module that adds a second factor therefore has to let the
user log in fully and then build a gate around an already-authenticated session,
and that gate has to cover, correctly and without omission:

- every login path, including ones that never touch the login form;
- authentication methods that present credentials on each request and never log
  in at all, such as HTTP Basic or API tokens — which core does not even let a
  module identify, because it does not record which provider authenticated a
  request;
- requests that fail routing, whose error pages core renders in a sub-request
  that is still authenticated as the user;
- cached pages, which can be served without the gate being consulted.

This release does all of that, and most of its code exists for that reason
rather than for the second factor itself. The approach is sound but it is the
wrong layer: every 2FA module must rediscover the same list.

A patch series has therefore been prepared for Drupal core, proposing that core
own the boundary instead: a login policy that can hold a login before any
session is established, so the user stays anonymous until verification is
complete, and an event that reports which provider authenticated a request so a
policy can refuse one. With those in place a module like this one supplies only
the factor, and there is no gate to get wrong. The same series makes credential
attempt limiting atomic, which is the other half of what was wrong here.

Those changes cannot help this release — they need to land in core first — so
nothing here depends on them. They are mentioned because the fix in this module
closes the holes without removing the reason they were easy to create.
