<?php

declare(strict_types=1);

namespace Drupal\Tests\magic_login\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\magic_login\MagicLinkManagerInterface;
use Drupal\user\Entity\User;
use Drupal\user\UserInterface;

/**
 * Token lifecycle, rate limiting and auto-registration.
 *
 * @group magic_login
 * @coversDefaultClass \Drupal\magic_login\MagicLinkManager
 */
final class MagicLinkManagerTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['system', 'user', 'magic_login'];

  /**
   * The manager under test.
   */
  private MagicLinkManagerInterface $manager;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->installEntitySchema('user');
    $this->installSchema('user', ['users_data']);
    $this->installConfig(['system', 'user', 'magic_login']);

    $this->manager = $this->container->get('magic_login.link_manager');
  }

  /**
   * A freshly issued token validates.
   *
   * @covers ::buildUrl
   * @covers ::validate
   */
  public function testValidTokenResolvesToAccount(): void {
    $account = $this->createAccount('ada@example.com');
    $timestamp = \Drupal::time()->getRequestTime();

    $hash = $this->hashFromUrl($account, $timestamp);
    $resolved = $this->manager->validate((int) $account->id(), $timestamp, $hash);

    $this->assertInstanceOf(UserInterface::class, $resolved);
    $this->assertSame($account->id(), $resolved->id());
  }

  /**
   * A token older than link_expiry is refused.
   *
   * @covers ::validate
   */
  public function testExpiredTokenIsRefused(): void {
    $account = $this->createAccount('ada@example.com');
    $expiry = (int) $this->config('magic_login.settings')->get('link_expiry');
    $issued = \Drupal::time()->getRequestTime() - $expiry - 1;

    $hash = $this->hashFromUrl($account, $issued);

    $this->assertNull($this->manager->validate((int) $account->id(), $issued, $hash));
  }

  /**
   * A future-dated token is refused rather than tolerated as clock skew.
   *
   * @covers ::validate
   */
  public function testFutureTokenIsRefused(): void {
    $account = $this->createAccount('ada@example.com');
    $future = \Drupal::time()->getRequestTime() + 600;

    $hash = $this->hashFromUrl($account, $future);

    $this->assertNull($this->manager->validate((int) $account->id(), $future, $hash));
  }

  /**
   * A tampered hash is refused.
   *
   * @covers ::validate
   */
  public function testForgedHashIsRefused(): void {
    $account = $this->createAccount('ada@example.com');
    $timestamp = \Drupal::time()->getRequestTime();

    $this->assertNull($this->manager->validate((int) $account->id(), $timestamp, 'not-a-real-hash'));
  }

  /**
   * Logging in retires every outstanding token for that account.
   *
   * This is the single-use guarantee: there is no token store, the login
   * timestamp is an HMAC input.
   *
   * @covers ::validate
   */
  public function testTokenIsRetiredByLogin(): void {
    $account = $this->createAccount('ada@example.com');
    $timestamp = \Drupal::time()->getRequestTime();
    $hash = $this->hashFromUrl($account, $timestamp);

    $this->assertNotNull($this->manager->validate((int) $account->id(), $timestamp, $hash));

    $account->setLastLoginTime($timestamp + 1)->save();

    $this->assertNull(
      $this->manager->validate((int) $account->id(), $timestamp, $hash),
      'A token stops validating once the account has logged in.',
    );
  }

  /**
   * A password change retires outstanding tokens.
   *
   * @covers ::validate
   */
  public function testTokenIsRetiredByPasswordChange(): void {
    $account = $this->createAccount('ada@example.com');
    $timestamp = \Drupal::time()->getRequestTime();
    $hash = $this->hashFromUrl($account, $timestamp);

    $account->setPassword('a-completely-different-password')->save();

    $this->assertNull($this->manager->validate((int) $account->id(), $timestamp, $hash));
  }

  /**
   * A blocked account cannot be signed in with a token issued while active.
   *
   * @covers ::validate
   */
  public function testBlockedAccountIsRefused(): void {
    $account = $this->createAccount('ada@example.com');
    $timestamp = \Drupal::time()->getRequestTime();
    $hash = $this->hashFromUrl($account, $timestamp);

    $account->block()->save();

    $this->assertNull($this->manager->validate((int) $account->id(), $timestamp, $hash));
  }

  /**
   * Unknown addresses do not create accounts while auto_register is off.
   *
   * @covers ::requestLink
   */
  public function testUnknownAddressWithoutAutoRegister(): void {
    $result = $this->manager->requestLink('nobody@example.com');

    $this->assertSame(MagicLinkManagerInterface::RESULT_NO_ACCOUNT, $result);
    $this->assertSame([], $this->loadByMail('nobody@example.com'));
  }

  /**
   * Unknown addresses create accounts while auto_register is on.
   *
   * @covers ::requestLink
   */
  public function testAutoRegisterCreatesActiveAccount(): void {
    $this->config('magic_login.settings')->set('auto_register', TRUE)->save();

    $result = $this->manager->requestLink('grace@example.com');

    $this->assertSame(MagicLinkManagerInterface::RESULT_SENT, $result);

    $accounts = $this->loadByMail('grace@example.com');
    $this->assertCount(1, $accounts);

    $account = reset($accounts);
    $this->assertTrue($account->isActive());
    $this->assertNotEmpty($account->getPassword(), 'Auto-created accounts get a random password, not a NULL one.');
  }

  /**
   * The blocked domain list wins over auto-registration.
   *
   * @covers ::requestLink
   */
  public function testBlockedDomainPreventsAutoRegister(): void {
    $this->config('magic_login.settings')
      ->set('auto_register', TRUE)
      ->set('blocked_domains', "mailinator.com\nexample.org")
      ->save();

    $this->assertSame(
      MagicLinkManagerInterface::RESULT_NO_ACCOUNT,
      $this->manager->requestLink('spam@example.org'),
    );
    $this->assertSame([], $this->loadByMail('spam@example.org'));
  }

  /**
   * A non-empty allow list excludes everything else.
   *
   * @covers ::requestLink
   */
  public function testAllowListExcludesOtherDomains(): void {
    $this->config('magic_login.settings')
      ->set('auto_register', TRUE)
      ->set('allowed_domains', 'example.com, staff.example.com')
      ->save();

    $this->assertSame(
      MagicLinkManagerInterface::RESULT_SENT,
      $this->manager->requestLink('ok@staff.example.com'),
    );
    $this->assertSame(
      MagicLinkManagerInterface::RESULT_NO_ACCOUNT,
      $this->manager->requestLink('nope@elsewhere.test'),
    );
  }

  /**
   * Username collisions are disambiguated rather than throwing.
   *
   * @covers ::requestLink
   */
  public function testUsernameCollisionIsResolved(): void {
    $this->createAccount('ada@example.com', 'ada');
    $this->config('magic_login.settings')->set('auto_register', TRUE)->save();

    $this->manager->requestLink('ada@other.test');

    $accounts = $this->loadByMail('ada@other.test');
    $this->assertCount(1, $accounts);
    $this->assertNotSame('ada', reset($accounts)->getAccountName());
  }

  /**
   * Rate limiting kicks in, and counts unknown addresses too.
   *
   * @covers ::requestLink
   */
  public function testEmailRateLimit(): void {
    $this->createAccount('ada@example.com');
    $limit = (int) $this->config('magic_login.settings')->get('flood_email_limit');

    for ($i = 0; $i < $limit; $i++) {
      $this->assertSame(
        MagicLinkManagerInterface::RESULT_SENT,
        $this->manager->requestLink('ada@example.com'),
        sprintf('Request %d of %d is allowed.', $i + 1, $limit),
      );
    }

    $this->assertSame(
      MagicLinkManagerInterface::RESULT_FLOODED,
      $this->manager->requestLink('ada@example.com'),
    );
  }

  /**
   * Malformed addresses are rejected before any storage or mail work.
   *
   * @covers ::requestLink
   */
  public function testInvalidAddress(): void {
    $this->assertSame(MagicLinkManagerInterface::RESULT_INVALID, $this->manager->requestLink('not-an-address'));
    $this->assertSame(MagicLinkManagerInterface::RESULT_INVALID, $this->manager->requestLink('   '));
  }

  /**
   * Creates a saved, active account.
   */
  private function createAccount(string $mail, ?string $name = NULL): UserInterface {
    $account = User::create([
      'name' => $name ?? explode('@', $mail)[0] . '_' . $this->randomMachineName(6),
      'mail' => $mail,
      'pass' => $this->randomMachineName(16),
      'status' => 1,
    ]);
    $account->save();

    return $account;
  }

  /**
   * Extracts the hash the manager would put in a link.
   */
  private function hashFromUrl(UserInterface $account, int $timestamp): string {
    return $this->manager->buildUrl($account, $timestamp)
      ->getRouteParameters()['hash'];
  }

  /**
   * Loads accounts by address.
   *
   * @return \Drupal\user\UserInterface[]
   *   Matching accounts.
   */
  private function loadByMail(string $mail): array {
    return $this->container->get('entity_type.manager')
      ->getStorage('user')
      ->loadByProperties(['mail' => $mail]);
  }

}
