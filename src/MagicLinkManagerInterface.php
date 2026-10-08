<?php

declare(strict_types=1);

namespace Drupal\magic_login;

use Drupal\Core\Url;
use Drupal\user\UserInterface;

/**
 * Issues and validates one-time, email-delivered sign-in links.
 */
interface MagicLinkManagerInterface {

  /**
   * Outcome: a link was generated and handed to the mail system.
   */
  public const RESULT_SENT = 'sent';

  /**
   * Outcome: no account exists and auto-registration did not apply.
   */
  public const RESULT_NO_ACCOUNT = 'no_account';

  /**
   * Outcome: the account exists but is blocked.
   */
  public const RESULT_BLOCKED = 'blocked';

  /**
   * Outcome: a new account was created, blocked until an admin approves it.
   */
  public const RESULT_PENDING = 'pending';

  /**
   * Outcome: a rate limit was hit.
   */
  public const RESULT_FLOODED = 'flooded';

  /**
   * Outcome: the address was syntactically invalid.
   */
  public const RESULT_INVALID = 'invalid';

  /**
   * Outcome: handing the message to the mail system failed.
   */
  public const RESULT_MAIL_FAILED = 'mail_failed';

  /**
   * Delivery method: a single-use sign-in link.
   */
  public const METHOD_LINK = 'link';

  /**
   * Delivery method: a single-use 6-digit code, typed on the sign-in page.
   */
  public const METHOD_CODE = 'code';

  /**
   * Digits in a sign-in code.
   */
  public const CODE_LENGTH = 6;

  /**
   * Handles a request for a sign-in link.
   *
   * Callers MUST NOT vary their user-facing response on the return value: doing
   * so turns this form into an account-enumeration oracle. The value is for
   * logging, tests and admin tooling only.
   *
   * @param string $email
   *   The submitted email address.
   * @param string|null $ip
   *   Client IP for rate limiting, or NULL to use the current request.
   * @param bool $allowSignup
   *   Create an account for an unknown address even when auto_register is
   *   off. The public sign-up form passes the public_signup setting here.
   * @param string $method
   *   self::METHOD_LINK (default) or self::METHOD_CODE. Links and codes share
   *   one rate limit.
   *
   * @return string
   *   One of the self::RESULT_* constants.
   */
  public function requestLink(string $email, ?string $ip = NULL, bool $allowSignup = FALSE, string $method = self::METHOD_LINK): string;

  /**
   * Checks a typed sign-in code and returns the account it signs in.
   *
   * Every call counts against the verification rate limits, and against the
   * code's own attempt budget; a code is discarded after too many wrong
   * tries, when it expires, and when it is used. As with requestLink(),
   * callers MUST show the same error for every failure.
   *
   * @param string $email
   *   The address the code was sent to.
   * @param string $code
   *   The code as typed (spaces and dashes are ignored).
   * @param string|null $ip
   *   Client IP for rate limiting, or NULL to use the current request.
   *
   * @return \Drupal\user\UserInterface|null
   *   The account, or NULL for a wrong, expired, used or rate-limited code.
   */
  public function verifyCode(string $email, string $code, ?string $ip = NULL): ?UserInterface;

  /**
   * Builds the absolute sign-in URL for an account.
   *
   * @param \Drupal\user\UserInterface $account
   *   The account to sign in.
   * @param int $timestamp
   *   Issue time, in seconds.
   *
   * @return \Drupal\Core\Url
   *   The absolute URL carrying the token.
   */
  public function buildUrl(UserInterface $account, int $timestamp): Url;

  /**
   * Validates a token and returns the account it signs in.
   *
   * @param int $uid
   *   The user ID from the URL.
   * @param int $timestamp
   *   The issue time from the URL.
   * @param string $hash
   *   The HMAC from the URL.
   *
   * @return \Drupal\user\UserInterface|null
   *   The account, or NULL if the token is expired, spent, forged, or belongs
   *   to a blocked account.
   */
  public function validate(int $uid, int $timestamp, string $hash): ?UserInterface;

}
