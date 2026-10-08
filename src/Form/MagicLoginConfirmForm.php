<?php

declare(strict_types=1);

namespace Drupal\magic_login\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;
use Drupal\magic_login\MagicLinkManagerInterface;
use Drupal\user\UserInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Landing page for a sign-in link.
 *
 * Why this is a form and not a controller that just logs you in
 * -------------------------------------------------------------
 * Corporate mail security (Outlook Safe Links, Mimecast, Proofpoint) and some
 * webmail previewers fetch every URL in an inbound message before a human ever
 * sees it. If a GET on the link authenticated, then:
 *
 *   1. The scanner burns the single-use token, and the real user arrives to a
 *      dead link -- the most common bug report filed against magic-link logins.
 *   2. The scanner is handed a valid session cookie. Nobody is driving it, but
 *      an authenticated session now exists somewhere it should not.
 *
 * So the GET renders a confirmation with a CSRF-protected POST button, and only
 * the POST calls user_login_finalize(). Automated fetchers do not POST.
 *
 * The page is open to signed-in visitors too. People often click the link in
 * a browser that is still signed in (to the same or another account); that
 * used to be a bare "access denied". The same account now just gets a
 * "you're already signed in"; another account is offered a switch.
 */
final class MagicLoginConfirmForm extends FormBase {

  public function __construct(
    protected MagicLinkManagerInterface $linkManager,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): self {
    return new self($container->get('magic_login.link_manager'));
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'magic_login_confirm_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(
    array $form,
    FormStateInterface $form_state,
    ?string $uid = NULL,
    ?string $timestamp = NULL,
    ?string $hash = NULL,
  ): array {
    $form['#cache']['max-age'] = 0;

    $account = $this->linkManager->validate((int) $uid, (int) $timestamp, (string) $hash);

    if (!$account instanceof UserInterface) {
      $form['expired'] = [
        '#theme' => 'status_messages',
        '#message_list' => [
          'error' => [
            $this->t('This sign-in link is no longer valid. Links expire after a short time and can only be used once.'),
          ],
        ],
      ];
      $form['retry'] = [
        '#type' => 'link',
        '#title' => $this->t('Request a new link'),
        '#url' => Url::fromRoute('magic_login.request'),
        '#attributes' => ['class' => ['button', 'button--primary']],
      ];
      return $form;
    }

    $current = $this->currentUser();
    if ((int) $current->id() === (int) $account->id()) {
      // Nothing to do, and the token stays unspent.
      $form['already'] = [
        '#markup' => '<p>' . $this->t('You are already signed in as %name.', [
          '%name' => $account->getEmail(),
        ]) . '</p>',
      ];
      $form['continue'] = [
        '#type' => 'link',
        '#title' => $this->t('Continue'),
        '#url' => magic_login_landing_url(),
        '#attributes' => ['class' => ['button', 'button--primary']],
      ];
      return $form;
    }

    // Stash only the identifiers; re-validate on submit so an expiry that
    // elapses between render and click is still caught.
    $form_state->set('magic_login_uid', (int) $uid);
    $form_state->set('magic_login_timestamp', (int) $timestamp);
    $form_state->set('magic_login_hash', (string) $hash);

    if ($current->isAuthenticated()) {
      $form['confirm'] = [
        '#markup' => '<p>' . $this->t('This browser is signed in as %current. Continuing will sign you out of that account and sign you in as %name.', [
          '%current' => $current->getEmail() ?: $current->getDisplayName(),
          '%name' => $account->getEmail(),
        ]) . '</p>',
      ];
    }
    else {
      $form['confirm'] = [
        '#markup' => '<p>' . $this->t('You are about to sign in as %name.', [
          '%name' => $account->getEmail(),
        ]) . '</p>',
      ];
    }

    $form['actions'] = ['#type' => 'actions'];
    $form['actions']['submit'] = [
      '#type' => 'submit',
      '#value' => $current->isAuthenticated()
        ? $this->t('Sign out and continue as @name', ['@name' => $account->getEmail()])
        : $this->t('Sign in'),
      '#button_type' => 'primary',
    ];

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    $account = $this->linkManager->validate(
      (int) $form_state->get('magic_login_uid'),
      (int) $form_state->get('magic_login_timestamp'),
      (string) $form_state->get('magic_login_hash'),
    );

    if (!$account instanceof UserInterface) {
      $form_state->setErrorByName('', $this->t('This sign-in link expired while this page was open. Please request a new one.'));
      return;
    }

    $form_state->set('magic_login_account', $account);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    /** @var \Drupal\user\UserInterface $account */
    $account = $form_state->get('magic_login_account');

    // Read before user_login_finalize() sets it.
    $firstSignIn = (int) $account->getLastLoginTime() === 0;

    $current = $this->currentUser();
    if ($current->isAuthenticated()) {
      // Switching accounts. Not user_logout(): its session_manager->destroy()
      // suppresses every later session write in this request, so the new
      // login would never reach the browser. Do what it does otherwise, then
      // drop the old session's data and record so nothing carries over.
      $this->getLogger('user')->info('Session closed for %name.', ['%name' => $current->getAccountName()]);
      \Drupal::moduleHandler()->invokeAll('user_logout', [$current]);
      $session = $this->getRequest()->getSession();
      $session->clear();
      $session->migrate(TRUE);
    }

    // Updates the account's login timestamp, which is what retires the token.
    user_login_finalize($account);

    $this->getLogger('magic_login')->notice('Session opened for %name via a sign-in link.', [
      '%name' => $account->getAccountName(),
    ]);

    $this->messenger()->addStatus($this->t('You are signed in.'));

    // Respects ?destination= via RedirectResponseSubscriber, which only honours
    // internal paths.
    if ($firstSignIn) {
      $form_state->setRedirect('magic_login.welcome');
    }
    else {
      $form_state->setRedirectUrl(magic_login_landing_url());
    }
  }

}
