<?php

declare(strict_types=1);

namespace Drupal\magic_login;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Component\Transliteration\TransliterationInterface;
use Drupal\Component\Utility\Crypt;
use Drupal\Component\Utility\EmailValidatorInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Core\Language\LanguageManagerInterface;
use Drupal\Core\Mail\MailManagerInterface;
use Drupal\Core\Password\PasswordGeneratorInterface;
use Drupal\Core\Site\Settings;
use Drupal\Core\Url;
use Drupal\user\UserInterface;
use Psr\Log\LoggerInterface;

/**
 * Default implementation of the magic link manager.
 *
 * Token design
 * ------------
 * The token is an HMAC over (uid, issue time, last login time, email, password
 * hash), keyed on the site hash salt. Two properties fall out of that:
 *
 *  - It is single-use. user_login_finalize() updates the account's login
 *    timestamp, which changes the HMAC input, so a spent link stops validating
 *    without any server-side token store to maintain or garbage collect.
 *  - It is invalidated by a password change or an email change, because both
 *    are inputs. A user who suspects a leaked link can kill it by logging in.
 *
 * Nothing here reuses core's password-reset token or the /user/reset route.
 * That is deliberate: reset links carry a 24h default lifetime and land the
 * user on a "set a new password" affordance, neither of which we want.
 */
final class MagicLinkManager implements MagicLinkManagerInterface {

  /**
   * Flood event name for per-IP limiting.
   */
  private const FLOOD_IP = 'magic_login.request_ip';

  /**
   * Flood event name for per-address limiting.
   */
  private const FLOOD_EMAIL = 'magic_login.request_email';

  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly MailManagerInterface $mailManager,
    private readonly LanguageManagerInterface $languageManager,
    private readonly FloodInterface $flood,
    private readonly TimeInterface $time,
    private readonly TransliterationInterface $transliteration,
    private readonly EmailValidatorInterface $emailValidator,
    private readonly PasswordGeneratorInterface $passwordGenerator,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function requestLink(string $email, ?string $ip = NULL): string {
    $email = trim($email);
    if ($email === '' || !$this->emailValidator->isValid($email)) {
      return self::RESULT_INVALID;
    }

    $config = $this->configFactory->get('magic_login.settings');

    // Rate limit before doing anything that costs a query or an email. The
    // email identifier is hashed so the flood table never holds addresses.
    $emailKey = Crypt::hashBase64(mb_strtolower($email) . Settings::getHashSalt());
    $ipAllowed = $this->flood->isAllowed(
      self::FLOOD_IP,
      (int) $config->get('flood_ip_limit'),
      (int) $config->get('flood_ip_window'),
      $ip,
    );
    $emailAllowed = $this->flood->isAllowed(
      self::FLOOD_EMAIL,
      (int) $config->get('flood_email_limit'),
      (int) $config->get('flood_email_window'),
      $emailKey,
    );
    if (!$ipAllowed || !$emailAllowed) {
      $this->logger->warning('Rate limit hit for a sign-in link request.');
      return self::RESULT_FLOODED;
    }

    // Register the attempt now, not on success. Otherwise repeated requests for
    // addresses that have no account are free, and the limiter tells an
    // attacker which addresses exist.
    $this->flood->register(self::FLOOD_IP, (int) $config->get('flood_ip_window'), $ip);
    $this->flood->register(self::FLOOD_EMAIL, (int) $config->get('flood_email_window'), $emailKey);

    $account = $this->loadByEmail($email);

    if (!$account instanceof UserInterface) {
      if (!$config->get('auto_register') || !$this->domainIsPermitted($email)) {
        return self::RESULT_NO_ACCOUNT;
      }
      $account = $this->createAccount($email);
      if (!$account instanceof UserInterface) {
        return self::RESULT_NO_ACCOUNT;
      }
    }

    if (!$account->isActive()) {
      $this->logger->notice('Sign-in link requested for blocked account %uid.', [
        '%uid' => $account->id(),
      ]);
      return self::RESULT_BLOCKED;
    }

    return $this->send($account) ? self::RESULT_SENT : self::RESULT_MAIL_FAILED;
  }

  /**
   * {@inheritdoc}
   */
  public function buildUrl(UserInterface $account, int $timestamp): Url {
    return Url::fromRoute('magic_login.confirm', [
      'uid' => $account->id(),
      'timestamp' => $timestamp,
      'hash' => $this->hash($account, $timestamp),
    ], ['absolute' => TRUE, 'language' => $this->languageManager->getLanguage($account->getPreferredLangcode())]);
  }

  /**
   * {@inheritdoc}
   */
  public function validate(int $uid, int $timestamp, string $hash): ?UserInterface {
    $now = $this->time->getRequestTime();
    $expiry = (int) $this->configFactory->get('magic_login.settings')->get('link_expiry');

    // Reject future-dated tokens outright rather than letting clock skew widen
    // the window.
    if ($timestamp > $now || ($now - $timestamp) > $expiry) {
      return NULL;
    }

    $account = $this->entityTypeManager->getStorage('user')->load($uid);
    if (!$account instanceof UserInterface || !$account->isActive() || (int) $account->id() === 0) {
      return NULL;
    }

    // hash_equals, not ==, so token comparison does not leak via timing.
    if (!hash_equals($this->hash($account, $timestamp), $hash)) {
      return NULL;
    }

    return $account;
  }

  /**
   * Computes the HMAC for an account/timestamp pair.
   */
  private function hash(UserInterface $account, int $timestamp): string {
    $data = implode(':', [
      'magic_login',
      $account->id(),
      $timestamp,
      // Changes on every successful login, which is what makes a spent link
      // stop working.
      $account->getLastLoginTime() ?? 0,
      $account->getEmail() ?? '',
      // Changes on every password change.
      $account->getPassword() ?? '',
    ]);

    return Crypt::hmacBase64($data, Settings::getHashSalt());
  }

  /**
   * Loads the single active-or-blocked account owning an address.
   */
  private function loadByEmail(string $email): ?UserInterface {
    $matches = $this->entityTypeManager->getStorage('user')
      ->loadByProperties(['mail' => $email]);

    // Drupal enforces uniqueness on mail, but a sloppy migration can leave
    // duplicates behind. Refusing to guess is safer than picking one.
    if (count($matches) !== 1) {
      if (count($matches) > 1) {
        $this->logger->error('Refusing to issue a sign-in link: @count accounts share one address.', [
          '@count' => count($matches),
        ]);
      }
      return NULL;
    }

    $account = reset($matches);
    return $account instanceof UserInterface ? $account : NULL;
  }

  /**
   * Creates an active account for an address.
   */
  private function createAccount(string $email): ?UserInterface {
    $storage = $this->entityTypeManager->getStorage('user');
    $config = $this->configFactory->get('magic_login.settings');

    /** @var \Drupal\user\UserInterface $account */
    $account = $storage->create([
      'name' => $this->generateUsername($email),
      'mail' => $email,
      // A random password the user never learns. It keeps the account from
      // having a NULL password (which would make the token input a constant)
      // and leaves the normal reset flow available if they ever want one.
      'pass' => $this->passwordGenerator->generate(32),
      'status' => 1,
      'langcode' => $this->languageManager->getCurrentLanguage()->getId(),
      'preferred_langcode' => $this->languageManager->getCurrentLanguage()->getId(),
      'init' => $email,
    ]);

    foreach ((array) $config->get('auto_register_roles') as $rid) {
      if (is_string($rid) && $rid !== '') {
        $account->addRole($rid);
      }
    }

    try {
      $violations = $account->validate();
      if ($violations->count() > 0) {
        $this->logger->error('Auto-registration rejected by entity validation: @messages', [
          '@messages' => implode('; ', array_map(
            static fn ($v) => (string) $v->getMessage(),
            iterator_to_array($violations),
          )),
        ]);
        return NULL;
      }
      $account->save();
    }
    catch (\Exception $e) {
      $this->logger->error('Auto-registration failed: @message', ['@message' => $e->getMessage()]);
      return NULL;
    }

    $this->logger->notice('Auto-created account %uid from a sign-in link request.', [
      '%uid' => $account->id(),
    ]);

    return $account;
  }

  /**
   * Derives an available username from an address.
   */
  private function generateUsername(string $email): string {
    $local = (string) strstr($email, '@', TRUE);
    $base = $this->transliteration->transliterate($local, 'en', '');
    $base = preg_replace('/[^A-Za-z0-9_.\- ]/', '', $base) ?? '';
    $base = trim((string) preg_replace('/\s+/', ' ', $base));

    if (mb_strlen($base) < 3) {
      $base = 'user';
    }
    // Leave headroom for the disambiguating suffix.
    $base = mb_substr($base, 0, UserInterface::USERNAME_MAX_LENGTH - 12);

    $storage = $this->entityTypeManager->getStorage('user');
    $candidate = $base;
    $suffix = 0;

    while ($storage->loadByProperties(['name' => $candidate])) {
      if (++$suffix > 50) {
        // Stop probing and take a random tail; collisions this deep mean the
        // base is a popular local part, not that we are one query away.
        $candidate = $base . '_' . bin2hex(random_bytes(4));
        break;
      }
      $candidate = $base . '_' . $suffix;
    }

    return $candidate;
  }

  /**
   * Applies the allow/deny domain lists to auto-registration.
   */
  private function domainIsPermitted(string $email): bool {
    $domain = mb_strtolower(substr((string) strrchr($email, '@'), 1));
    if ($domain === '') {
      return FALSE;
    }

    $config = $this->configFactory->get('magic_login.settings');
    $blocked = $this->parseDomainList((string) $config->get('blocked_domains'));
    if ($blocked !== [] && in_array($domain, $blocked, TRUE)) {
      return FALSE;
    }

    $allowed = $this->parseDomainList((string) $config->get('allowed_domains'));
    return $allowed === [] || in_array($domain, $allowed, TRUE);
  }

  /**
   * Splits an admin-entered domain list into normalised domains.
   *
   * @return string[]
   *   Lowercased domains, leading "@" and "." stripped.
   */
  private function parseDomainList(string $raw): array {
    $parts = preg_split('/[\s,]+/', mb_strtolower(trim($raw))) ?: [];

    return array_values(array_filter(array_map(
      static fn (string $item): string => ltrim(trim($item), '@.'),
      $parts,
    )));
  }

  /**
   * Hands a link message to the mail system.
   */
  private function send(UserInterface $account): bool {
    $timestamp = $this->time->getRequestTime();
    $langcode = $account->getPreferredLangcode();

    $message = $this->mailManager->mail('magic_login', 'link', $account->getEmail(), $langcode, [
      'account' => $account,
      'url' => $this->buildUrl($account, $timestamp)->toString(),
      'expiry' => (int) $this->configFactory->get('magic_login.settings')->get('link_expiry'),
    ]);

    if (empty($message['result'])) {
      $this->logger->error('Failed to send a sign-in link to account %uid.', ['%uid' => $account->id()]);
      return FALSE;
    }

    $this->logger->info('Sign-in link sent to account %uid.', ['%uid' => $account->id()]);
    return TRUE;
  }

}
