<?php

declare(strict_types=1);

namespace Drupal\magic_login\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;
use Drupal\magic_login\MagicLinkManagerInterface;
use Drupal\user\UserInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Public "sign in or create your account" page at /signin.
 *
 * There is no separate sign-up: a new address gets an account the first time
 * it signs in. Site rules (terms to accept, where people may sign up from)
 * are added by a site module's form alter. Until the public_signup setting is
 * on, the page renders with a disabled button, and validateForm() refuses
 * submissions as well, since a disabled attribute alone stops nobody.
 */
final class MagicLoginSignupForm extends FormBase {

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
    return 'magic_login_signup_form';
  }

  /**
   * Open only with public_signup on and core registration not admin-only.
   */
  private function isOpen(): bool {
    return (bool) $this->config('magic_login.settings')->get('public_signup')
      && $this->config('user.settings')->get('register') !== UserInterface::REGISTER_ADMINISTRATORS_ONLY;
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    // Closed: no page at all, rather than a disabled form advertising one.
    if (!$this->isOpen()) {
      throw new NotFoundHttpException();
    }
    $form['#cache']['max-age'] = 0;
    $open = TRUE;

    $form['intro'] = [
      '#markup' => '<p>' . $this->t('New here or coming back? It works the same way. Type your email and we’ll send you a link or code to sign in. New here? We’ll make your account for you.') . '</p>',
    ];

    // Always-visible information, not a collapsible section: nothing to click.
    $form['how'] = [
      '#type' => 'container',
      '#attributes' => ['class' => ['magic-login-how']],
      'title' => [
        '#type' => 'html_tag',
        '#tag' => 'h2',
        '#value' => $this->t('How signing in works'),
      ],
      'text' => [
        '#theme' => 'item_list',
        '#items' => [
          // Short, plain words: for anyone, including people new to computers.
          $this->t('You don’t need a password. Just your email.'),
          $this->t('Type your email and tap the button.'),
          $this->t('We’ll email you a link or a 6-digit code. Tap the link, or type the code here.'),
          $this->t('It works once, for a few minutes. Need a new one? Just ask again.'),
          $this->t('Only someone who can open your email can sign in as you.'),
        ],
      ],
    ];

    $form['mail'] = [
      '#type' => 'email',
      '#title' => $this->t('Email address'),
      '#required' => $open,
      '#disabled' => !$open,
      '#attributes' => [
        'autocomplete' => 'email',
        'autocapitalize' => 'none',
        'autocorrect' => 'off',
        'spellcheck' => 'false',
      ],
    ];

    $form['approval'] = magic_login_approval_notice();

    $form['actions'] = ['#type' => 'actions'];
    $form['actions']['methods'] = magic_login_method_buttons((string) $this->t('Email me a sign-in link'), ['#disabled' => !$open]);
    $form['#attached']['library'][] = 'magic_login/forms';

    if (!$open) {
      $form['closed'] = [
        '#markup' => '<p><strong>' . $this->t('Sign-up opens soon.') . '</strong> ' . $this->t('Already have an account? <a href=":url">Sign in here</a>.', [
          ':url' => Url::fromRoute('user.login')->toString(),
        ]) . '</p>',
        '#weight' => 100,
      ];
    }

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    if (!$this->isOpen()) {
      $form_state->setErrorByName('', $this->t('Sign-up is not open yet.'));
      return;
    }
    // Site rules (who may sign up, terms to accept...) belong in a site
    // module's hook_form_magic_login_signup_form_alter().
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    if (magic_login_code_pressed($form_state)) {
      magic_login_request_code((string) $form_state->getValue('mail'), TRUE);
      if (magic_login_requires_approval()) {
        $this->messenger()->addStatus($this->t('If you’re new, we’ve emailed you about your new account instead. It will be ready once we approve it.'));
      }
      $form_state->setRedirect('magic_login.code');
      return;
    }
    $ip = $this->getRequest()->getClientIp();
    $this->linkManager->requestLink((string) $form_state->getValue('mail'), $ip, TRUE);

    // Same message whatever happened, so the page does not reveal which
    // addresses already have accounts.
    $this->messenger()->addStatus(magic_login_requires_approval()
      ? $this->t('Check your email. If you have an account, we’ve sent you a sign-in link. If you’re new, we’ve emailed you about your new account. It will be ready once we approve it, usually within a day.')
      : $this->t('Check your email. We’ve sent you a sign-in link. Tap it to open your account. It works once, for @minutes minutes.', [
        '@minutes' => (int) round((int) $this->config('magic_login.settings')->get('link_expiry') / 60),
      ]));
    $form_state->setRedirect('magic_login.signup');
  }

}
