# Magic Login

Single-use, email-delivered sign-in links for Drupal 10.3+ / 11, with optional
account creation the first time an address is seen.

Built because the contrib options (`magic_link`, `magic_login_link`,
`dripyard_simple_login`, `passwordless`) are all existing-user-only — none of
them remove the signup step, which was the actual requirement.

## Install

```
cp -r magic_login web/modules/custom/
drush en magic_login
drush cr
```

Configure at **Administration → Configuration → People → Magic Login**
(`/admin/config/people/magic-login`).

## Site-specific behaviour

The module is project-agnostic. What a site decides is in settings, or in the
site's own code:

- `landing_path`: where people land after signing in (default `/`; the first
  sign-in shows the welcome step, titled "Welcome to [site name]", first).
- `signup_role_permissions` / `signup_role_excluded`: a role is only ever given
  to a self-created account if it is not an admin role, not excluded, and has
  no permission outside the list (default: no permissions at all).
- Who may sign up and what they agree to: add fields and validators in a site
  module's `hook_form_magic_login_signup_form_alter()` (e.g. a terms checkbox,
  a country rule).
- How the emails look: plain text here, with optional hints for an HTML mail
  system (e.g. the html_mail module and a theme's `html-mail.html.twig`).

## No passwords for customers

Only administrators (a role marked as the admin role, or uid 1:
`magic_login_uses_passwords()`) work with passwords. For everyone else, the
account edit form shows nothing about passwords: Current password,
Password, Confirm password, the strength meter and "Reset your password"
are removed (`#access` FALSE, so submitted values are ignored too). Core
only lets an account change its own email with the current password, which
a passwordless account does not have, so the email is shown read-only with
a pointer to the contact page; administrators can still change it.
/user/password is hidden as well (`PasswordRouteSubscriber`).

## How the token works

The token is an HMAC over `(uid, issue time, last login time, email, password
hash)`, keyed on the site hash salt. There is no token table.

Two properties fall out of that construction:

- **Single-use.** `user_login_finalize()` updates the account's login
  timestamp, which is an HMAC input, so a spent link stops validating. No
  storage to maintain, no garbage collection, no race between two requests
  redeeming the same token.
- **Revocable.** A password change or email change also invalidates every
  outstanding link, because both are inputs. If someone suspects a leaked link,
  logging in kills it.

Expiry is a separate upper bound (`link_expiry`, default 900s). Future-dated
timestamps are rejected outright rather than being tolerated as clock skew, and
comparison uses `hash_equals()`.

This deliberately does **not** reuse core's password-reset token or the
`/user/reset` route. Reset links default to a 24-hour lifetime and land the user
on a "set a new password" affordance; neither is wanted here.

## Sign-in codes

Every sign-in form offers two buttons: **Email me a sign-in link** and **Email
me a 6-digit code**. Links and codes share the request rate limit.

A code goes to `/user/login/code` (`MagicLoginCodeForm`), which already knows
the address from the session. The field is `autocomplete="one-time-code"`,
`inputmode="numeric"`, so iOS Security Code AutoFill ("From Mail") and Android
keyboards offer the code from the email; six digits submit the form by
themselves (`js/magic_login_code.js`).

The script draws six digit boxes (`.magic-login-otp__cell`) over that **one**
field, which stays on top, see-through, so taps, typing, paste, autofill and
screen readers all still reach a single input (phones fill one field, not
six). A paste takes the code out of a whole copied sentence ("Your code is:
123456"); the server does the same (`verifyCode()` keeps only the digits).
`css/magic_login.css` holds only the boxes' structure; a theme skins them.
Without JavaScript it is a plain field.

The email puts the code first in the
subject (`123456 is your Example Site sign-in code`) and the first line, next to
the word "code", with no other long numbers: that is what the phones' detection
looks for. Plain text, like the link email.

Security:

- Six random digits (`random_int`), too short to be stateless, so one pending
  code per address lives in the expirable key/value store (`magic_login_code`,
  keyed by the hashed address). Only an HMAC of the code is stored, over the
  same account state as a link token, so a sign-in by any route, or a password
  or email change, kills it.
- Single use; expires after `code_expiry` (600 s); discarded after
  `code_max_attempts` (5) wrong tries; a new request replaces the old code.
- Every attempt, right or wrong, counts against `flood_verify_ip_limit` (30)
  and `flood_verify_email_limit` (10) per `flood_verify_window` (1 h). With 3
  codes an hour per address, that is at most ~15 guesses an hour at 1 in a
  million each.
- Constant-time comparison; one error message for every failure; the code page
  reads the same whether or not the address has an account.
- The CAPTCHA (Altcha) is on every form that sends or checks a code, including
  the code page, and a failed CAPTCHA stops before any guess is made. The code
  page starts the Altcha check itself on load (its field has focus from the
  start, so "check on focus" would never fire).

**CAPTCHA and `#limit_validation_errors`.** Never put
`#limit_validation_errors` on a button that must be CAPTCHA-protected: the
captcha module's `processCaptchaElement()` skips the CAPTCHA entirely for such
a button. The login-form buttons therefore make the hidden username/password
fields optional instead (core still rejects an empty password login in
`UserLoginForm::validateFinal()`). Checked on the live site: a POST without the
Altcha solution is refused by every sign-in button.

## Why the link lands on a confirmation page

`GET /user/login/magic/{uid}/{timestamp}/{hash}` renders a form. Only the POST
authenticates.

This is not ceremony. Corporate mail security — Outlook Safe Links, Mimecast,
Proofpoint — and some webmail previewers fetch every URL in an inbound message
before a human sees it. If the GET authenticated:

1. The scanner burns the single-use token and the real user arrives at a dead
   link. This is the single most common bug report filed against magic-link
   implementations.
2. The scanner is handed a valid session cookie.

Automated fetchers do not POST. `dripyard_simple_login` and anything else built
directly on `user.reset.login` authenticate on GET and have this problem.

## Account enumeration

Every outcome — link sent, no such account, rate limited, blocked account,
mail failure — produces the same user-facing message and the same redirect.

`MagicLinkManagerInterface::requestLink()` returns a `RESULT_*` constant for
logging and tests. **Do not branch your UI on it.**

Rate limiting registers the attempt before the account lookup, so repeated
probes for non-existent addresses are not free and the limiter itself does not
leak which addresses exist. The flood identifier is a hash of the address, so
the `flood` table never holds raw email addresses.

## Rate limits

Defaults: 3 requests per address per hour, 20 per IP per hour.

Do not raise these casually. Without them the request form is an open relay for
sending mail to arbitrary addresses, with your domain's reputation attached.

## Auto-registration

Off by default. When enabled, an unrecognised address gets an account with:

- a username derived from the local part, transliterated and disambiguated
  against existing names
- a random 32-character password the user never learns (so the account has a
  real password hash rather than `NULL`, and the normal reset flow stays
  available)
- `status: 1` and any roles configured on the settings form

This **bypasses** `user.settings:register` by design — that is what removes the
signup step. Allow and deny domain lists gate it; the deny list is checked
first.

## Things to decide before you turn this on

- **uid 1.** Nothing here excludes the admin account. A magic link to a
  compromised mailbox is then a full site takeover with no password needed. If
  that bothers you, add a uid/role check in `MagicLinkManager::requestLink()`,
  or keep uid 1 on an address that isn't in your normal inbox.
- **Email case sensitivity.** Lookup uses `loadByProperties(['mail' => ...])`,
  matching core. MySQL's default collation makes that case-insensitive;
  Postgres makes it case-sensitive, so `Ada@example.com` and `ada@example.com`
  can end up as two accounts. Normalise on input if that matters to you.
- **Mail deliverability.** A link that lands in spam is a login that silently
  fails. If the site is not already sending transactional mail through
  something with SPF/DKIM aligned, sort that out first — this module makes mail
  delivery load-bearing for site access.
- **Duplicate addresses.** If a migration left two accounts sharing an address,
  the manager logs an error and refuses to issue a link rather than guessing.

## Tests

```
vendor/bin/phpunit -c core --group magic_login
```

Kernel tests cover the token lifecycle (valid, expired, future-dated, forged,
retired by login, retired by password change, blocked account), the code
lifecycle (single use, attempts cap, expiry, retired by sign-in, the emailed
subject, the per-address attempt limit),
auto-registration, domain gating, username collision handling and rate limiting.

Functional tests cover the end-to-end flow, single use, the GET-does-not-
authenticate guarantee, byte-identical responses for known and unknown
addresses, and the login-form button not consuming the core login flood budget.

## Layout

```
magic_login.info.yml
magic_login.module              hook_mail, login form integration
magic_login.routing.yml
magic_login.services.yml
config/install/                 default settings
config/schema/                  config schema
src/MagicLinkManagerInterface.php
src/MagicLinkManager.php        token generation/validation, flood, registration
src/Form/MagicLoginRequestForm.php    /user/login/link
src/Form/MagicLoginConfirmForm.php    the POST-to-authenticate landing page
src/Form/MagicLoginCodeForm.php       /user/login/code: enter a 6-digit code
js/magic_login_code.js          digits only, auto-submit, starts the Altcha check
css/magic_login.css             link-or-code buttons, the code field
src/Form/SettingsForm.php
tests/src/Kernel/
tests/src/Functional/
```

All collaborators are constructor-injected; there is no `\Drupal::` service
lookup in `src/`. The `.module` file uses the static accessors because
procedural hooks have no container to inject into.
