<?php

declare(strict_types=1);

namespace Drupal\magic_login;

use Drupal\user\RoleInterface;
use Drupal\Component\Datetime\TimeInterface;
use Drupal\Component\Transliteration\TransliterationInterface;
use Drupal\Component\Utility\Crypt;
use Drupal\Component\Utility\EmailValidatorInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface;
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
 * Sign-in codes
 * --------------
 * A code is six random digits, too short to be stateless, so one pending code
 * per address is kept in the expirable key/value store (collection
 * magic_login_code, keyed by the same address hash the flood table uses).
 * Only an HMAC of the code is stored, over the same account state as a link
 * (last login, email, password hash), so a code also dies when the account
 * signs in by any route. Wrong guesses are capped per code (code_max_attempts,
 * then it is discarded) and rate limited per address and per IP; with three
 * codes an hour per address, that is at most ~15 guesses an hour against a
 * million possibilities.
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

  /**
   * Flood event names for code verification attempts.
   */
  private const FLOOD_VERIFY_IP = 'magic_login.verify_ip';
  private const FLOOD_VERIFY_EMAIL = 'magic_login.verify_email';

  /**
   * Expirable key/value collection holding pending codes.
   */
  private const CODE_COLLECTION = 'magic_login_code';

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
    private readonly KeyValueExpirableFactoryInterface $keyValueExpirable,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function requestLink(string $email, ?string $ip = NULL, bool $allowSignup = FALSE, string $method = self::METHOD_LINK): string {
    $email = trim($email);
    if ($email === '' || !$this->emailValidator->isValid($email)) {
      return self::RESULT_INVALID;
    }
    $method = $method === self::METHOD_CODE ? self::METHOD_CODE : self::METHOD_LINK;

    $config = $this->configFactory->get('magic_login.settings');

    // Rate limit before doing anything that costs a query or an email. The
    // email identifier is hashed so the flood table never holds addresses.
    $emailKey = $this->emailKey($email);
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
      if (!$this->accountCreationAllowed($allowSignup) || !$this->domainIsPermitted($email)) {
        return self::RESULT_NO_ACCOUNT;
      }
      $account = $this->createAccount($email);
      if (!$account instanceof UserInterface) {
        return self::RESULT_NO_ACCOUNT;
      }
      if (!$account->isActive()) {
        // Blocked until an admin approves it: no sign-in link yet. The user
        // gets "pending approval", the site address gets the admin copy.
        _user_mail_notify('register_pending_approval', $account);
        return self::RESULT_PENDING;
      }
      // Approval is off: the account is live, so fall through and send its
      // first link. Nothing is usable until that link is clicked.
    }

    if (!$account->isActive()) {
      $this->logger->notice('Sign-in link requested for blocked account %uid.', [
        '%uid' => $account->id(),
      ]);
      return self::RESULT_BLOCKED;
    }

    $sent = $method === self::METHOD_CODE ? $this->sendCode($account, $emailKey) : $this->send($account);
    return $sent ? self::RESULT_SENT : self::RESULT_MAIL_FAILED;
  }

  /**
   * {@inheritdoc}
   */
  public function verifyCode(string $email, string $code, ?string $ip = NULL): ?UserInterface {
    $email = trim($email);
    // Only the digits count: "123 456", "123-456", or a pasted sentence
    // ("Your code is: 123456"). Anything that is not then exactly the right
    // number of digits is simply wrong.
    $code = preg_replace('/\D+/', '', $code) ?? '';
    if ($email === '' || !preg_match('/^\d{' . self::CODE_LENGTH . '}$/', $code)) {
      return NULL;
    }

    $config = $this->configFactory->get('magic_login.settings');
    $emailKey = $this->emailKey($email);
    $window = (int) ($config->get('flood_verify_window') ?: 3600);
    if (!$this->flood->isAllowed(self::FLOOD_VERIFY_IP, (int) ($config->get('flood_verify_ip_limit') ?: 30), $window, $ip)
      || !$this->flood->isAllowed(self::FLOOD_VERIFY_EMAIL, (int) ($config->get('flood_verify_email_limit') ?: 10), $window, $emailKey)) {
      $this->logger->warning('Rate limit hit for sign-in code verification.');
      return NULL;
    }
    // Every attempt counts, right or wrong.
    $this->flood->register(self::FLOOD_VERIFY_IP, $window, $ip);
    $this->flood->register(self::FLOOD_VERIFY_EMAIL, $window, $emailKey);

    $store = $this->keyValueExpirable->get(self::CODE_COLLECTION);
    $pending = $store->get($emailKey);
    if (!is_array($pending) || !isset($pending['uid'], $pending['created'], $pending['hash'])) {
      return NULL;
    }

    $now = $this->time->getRequestTime();
    $expiry = $this->codeExpiry();
    $maxAttempts = (int) ($config->get('code_max_attempts') ?: 5);
    if ($now - (int) $pending['created'] > $expiry || $now < (int) $pending['created'] || (int) ($pending['attempts'] ?? 0) >= $maxAttempts) {
      $store->delete($emailKey);
      return NULL;
    }

    $account = $this->entityTypeManager->getStorage('user')->load((int) $pending['uid']);
    if (!$account instanceof UserInterface || !$account->isActive() || (int) $account->id() === 0
      || mb_strtolower((string) $account->getEmail()) !== mb_strtolower($email)) {
      $store->delete($emailKey);
      return NULL;
    }

    if (!hash_equals($this->codeHash($account, (int) $pending['created'], $code), (string) $pending['hash'])) {
      $pending['attempts'] = (int) ($pending['attempts'] ?? 0) + 1;
      if ($pending['attempts'] >= $maxAttempts) {
        $store->delete($emailKey);
        $this->logger->notice('Sign-in code for account %uid discarded after too many wrong attempts.', ['%uid' => $account->id()]);
      }
      else {
        $store->setWithExpire($emailKey, $pending, max(1, $expiry - ($now - (int) $pending['created'])));
      }
      return NULL;
    }

    // Single use: gone now, and the login that follows changes the HMAC
    // input as well.
    $store->delete($emailKey);
    return $account;
  }

  /**
   * Issues a new code for an account, replacing any pending one.
   *
   * Returns the code. Public for tests and admin tooling; normal use goes
   * through requestLink(..., METHOD_CODE).
   */
  public function issueCode(UserInterface $account): string {
    $code = str_pad((string) random_int(0, 10 ** self::CODE_LENGTH - 1), self::CODE_LENGTH, '0', STR_PAD_LEFT);
    $created = $this->time->getRequestTime();
    $this->keyValueExpirable->get(self::CODE_COLLECTION)->setWithExpire($this->emailKey((string) $account->getEmail()), [
      'uid' => (int) $account->id(),
      'created' => $created,
      'hash' => $this->codeHash($account, $created, $code),
      'attempts' => 0,
    ], $this->codeExpiry());
    return $code;
  }

  /**
   * Seconds a code stays valid.
   */
  private function codeExpiry(): int {
    return (int) ($this->configFactory->get('magic_login.settings')->get('code_expiry') ?: 600);
  }

  /**
   * The flood/storage identifier for an address: never the address itself.
   */
  private function emailKey(string $email): string {
    return Crypt::hashBase64(mb_strtolower(trim($email)) . Settings::getHashSalt());
  }

  /**
   * HMAC of a code, bound to the account's current state like a link.
   */
  private function codeHash(UserInterface $account, int $created, string $code): string {
    return Crypt::hmacBase64(implode(':', [
      'magic_login_code',
      $account->id(),
      $created,
      $code,
      $account->getLastLoginTime() ?? 0,
      $account->getEmail() ?? '',
      $account->getPassword() ?? '',
    ]), Settings::getHashSalt());
  }

  /**
   * Emails a new sign-in code.
   */
  private function sendCode(UserInterface $account, string $emailKey): bool {
    $code = $this->issueCode($account);
    $message = $this->mailManager->mail('magic_login', 'code', $account->getEmail(), $account->getPreferredLangcode(), [
      'account' => $account,
      'code' => $code,
      'expiry' => $this->codeExpiry(),
    ]);
    if (empty($message['result'])) {
      $this->keyValueExpirable->get(self::CODE_COLLECTION)->delete($emailKey);
      $this->logger->error('Failed to send a sign-in code to account %uid.', ['%uid' => $account->id()]);
      return FALSE;
    }
    $this->logger->info('Sign-in code sent to account %uid.', ['%uid' => $account->id()]);
    return TRUE;
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
      // having a NULL password (which would make the token input a constant).
      'pass' => $this->passwordGenerator->generate(32),
      // Self-created accounts wait for admin approval unless it is turned off.
      'status' => magic_login_requires_approval() ? 0 : 1,
      'langcode' => $this->languageManager->getCurrentLanguage()->getId(),
      'preferred_langcode' => $this->languageManager->getCurrentLanguage()->getId(),
      'init' => $email,
    ]);

    foreach ((array) $config->get('auto_register_roles') as $rid) {
      if (!is_string($rid) || $rid === '') {
        continue;
      }
      if (!self::isSafeSignupRole($rid)) {
        $this->logger->error('Refused to give role %rid to a self-created account: it is excluded, or has permissions beyond signup_role_permissions.', ['%rid' => $rid]);
        continue;
      }
      $account->addRole($rid);
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
   * Whether an unknown address may get a new account.
   *
   * Never while core's "Who can register accounts?" is "Administrators only"
   * (user.settings:register = admin_only), whatever this module's own
   * settings say or what the caller asks for: that core setting is the
   * site-wide "visitors cannot create accounts" switch. Otherwise, the
   * public sign-up form (when public_signup is on) or auto_register.
   */
  private function accountCreationAllowed(bool $allowSignup): bool {
    if ($this->configFactory->get('user.settings')->get('register') === UserInterface::REGISTER_ADMINISTRATORS_ONLY) {
      return FALSE;
    }
    $config = $this->configFactory->get('magic_login.settings');
    return ($allowSignup && $config->get('public_signup')) || $config->get('auto_register');
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

  /**
   * Whether a role is limited enough for a self-created account.
   *
   * Not admin, not listed in signup_role_excluded, and no permission
   * outside signup_role_permissions (empty: the role may have none). Checked
   * when the account is created, so a role that gains permissions later
   * stops being assigned.
   */
  public static function isSafeSignupRole(string $rid): bool {
    $config = \Drupal::config('magic_login.settings');
    $excluded = array_merge(['anonymous', 'authenticated'], (array) $config->get('signup_role_excluded'));
    if (in_array($rid, $excluded, TRUE)) {
      return FALSE;
    }
    $role = \Drupal::entityTypeManager()->getStorage('user_role')->load($rid);
    if (!$role instanceof RoleInterface || $role->isAdmin()) {
      return FALSE;
    }
    return array_diff($role->getPermissions(), (array) $config->get('signup_role_permissions')) === [];
  }

  /**
   * Emails a sign-in link to an account.
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
