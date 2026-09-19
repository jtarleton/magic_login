<?php

declare(strict_types=1);

namespace Drupal\Tests\magic_login\Functional;

use Drupal\Core\Test\AssertMailTrait;
use Drupal\Tests\BrowserTestBase;
use Drupal\user\Entity\User;

/**
 * End-to-end sign-in flow.
 *
 * @group magic_login
 */
final class MagicLoginTest extends BrowserTestBase {

  use AssertMailTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['magic_login'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Requesting, then following, a link signs the user in.
   */
  public function testRequestAndFollowLink(): void {
    $account = $this->drupalCreateUser();

    $this->drupalGet('user/login/link');
    $this->submitForm(['mail' => $account->getEmail()], 'Email me a sign-in link');
    $this->assertSession()->pageTextContains('If that address belongs to an account');

    $url = $this->extractLink();
    $this->assertNotNull($url, 'A sign-in link was mailed.');

    // The GET must not authenticate -- it renders a confirmation instead.
    $this->drupalGet($url);
    $this->assertSession()->pageTextContains('You are about to sign in as');
    $this->assertFalse($this->drupalUserIsLoggedIn($account), 'A GET on the link does not open a session.');

    $this->submitForm([], 'Sign in');
    $this->assertTrue($this->drupalUserIsLoggedIn($account));
  }

  /**
   * A link works exactly once.
   */
  public function testLinkIsSingleUse(): void {
    $account = $this->drupalCreateUser();

    $this->drupalGet('user/login/link');
    $this->submitForm(['mail' => $account->getEmail()], 'Email me a sign-in link');
    $url = $this->extractLink();

    $this->drupalGet($url);
    $this->submitForm([], 'Sign in');
    $this->assertTrue($this->drupalUserIsLoggedIn($account));

    $this->drupalLogout();

    $this->drupalGet($url);
    $this->assertSession()->pageTextContains('This sign-in link is no longer valid');
    $this->assertFalse($this->drupalUserIsLoggedIn($account));
  }

  /**
   * An unknown address gets the same response as a known one.
   */
  public function testResponseDoesNotLeakAccountExistence(): void {
    $account = $this->drupalCreateUser();

    $this->drupalGet('user/login/link');
    $this->submitForm(['mail' => $account->getEmail()], 'Email me a sign-in link');
    $known = $this->getSession()->getPage()->getContent();

    $this->drupalGet('user/login/link');
    $this->submitForm(['mail' => 'nobody@example.com'], 'Email me a sign-in link');
    $unknown = $this->getSession()->getPage()->getContent();

    $this->assertSession()->pageTextContains('If that address belongs to an account');
    $this->assertSame(
      $this->stripVolatile($known),
      $this->stripVolatile($unknown),
      'The response is byte-identical whether or not the account exists.',
    );
  }

  /**
   * The inline login form button does not burn the core login flood budget.
   */
  public function testLoginFormButtonSkipsAuthValidators(): void {
    $account = $this->drupalCreateUser();

    $this->drupalGet('user/login');
    $this->submitForm(
      ['magic_login_mail' => $account->getEmail()],
      'Email me a sign-in link',
    );

    $this->assertSession()->pageTextContains('If that address belongs to an account');
    $this->assertSession()->pageTextNotContains('Unrecognized username or password');

    // The account must still be able to log in with a password afterwards.
    $this->drupalLogin($account);
    $this->assertTrue($this->drupalUserIsLoggedIn($account));
  }

  /**
   * Auto-registration creates an account for a new address.
   */
  public function testAutoRegistration(): void {
    $this->config('magic_login.settings')->set('auto_register', TRUE)->save();

    $this->drupalGet('user/login/link');
    $this->submitForm(['mail' => 'newcomer@example.com'], 'Email me a sign-in link');

    $url = $this->extractLink();
    $this->assertNotNull($url);

    $this->drupalGet($url);
    $this->submitForm([], 'Sign in');
    $this->assertSession()->pageTextContains('You are signed in.');

    $accounts = \Drupal::entityTypeManager()->getStorage('user')
      ->loadByProperties(['mail' => 'newcomer@example.com']);
    $this->assertCount(1, $accounts);
  }

  /**
   * A blocked account cannot sign in with a link.
   */
  public function testBlockedAccountCannotSignIn(): void {
    $account = $this->drupalCreateUser();

    $this->drupalGet('user/login/link');
    $this->submitForm(['mail' => $account->getEmail()], 'Email me a sign-in link');
    $url = $this->extractLink();

    User::load($account->id())->block()->save();

    $this->drupalGet($url);
    $this->assertSession()->pageTextContains('This sign-in link is no longer valid');
  }

  /**
   * Pulls the sign-in URL out of the most recent captured mail.
   */
  private function extractLink(): ?string {
    $mails = $this->getMails();
    if ($mails === []) {
      return NULL;
    }

    $body = (string) end($mails)['body'];
    preg_match('#https?://\S+/user/login/magic/\S+#', $body, $matches);

    return $matches[0] ?? NULL;
  }

  /**
   * Removes per-request noise so two responses can be compared byte for byte.
   */
  private function stripVolatile(string $html): string {
    // Form build IDs and CSRF tokens differ per request by design.
    return (string) preg_replace('/(form_build_id|form_token)[^>]*value="[^"]*"/', '$1', $html);
  }

}
