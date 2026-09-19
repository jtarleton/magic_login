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
   *
   * @return string
   *   One of the self::RESULT_* constants.
   */
  public function requestLink(string $email, ?string $ip = NULL): string;

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
