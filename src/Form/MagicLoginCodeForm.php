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
 * "Enter your code" page at /user/login/code.
 *
 * Reached after asking for a code on any sign-in form; the address it went to
 * is in the session (MAGIC_LOGIN_CODE_SESSION). Opened directly, it asks for
 * the address too.
 *
 * The code field is autocomplete="one-time-code" with a numeric keypad, so
 * iOS (Security Code AutoFill, "From Mail") and Android keyboards offer the
 * code from the email; six digits submit the form by themselves
 * (js/magic_login_code.js).
 *
 * Security: MagicLinkManager::verifyCode() does the work (single use, expiry,
 * attempts per code, rate limits per address and IP, constant-time compare).
 * Every failure shows the same message, whatever the reason, and the page
 * looks the same whether or not the address has an account. The form also
 * carries the site's CAPTCHA (Altcha), like the forms that send codes.
 */
final class MagicLoginCodeForm extends FormBase {

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
    return 'magic_login_code_form';
  }

  /**
   * The address the code went to, from the session.
   */
  private function sessionEmail(): string {
    return (string) $this->getRequest()->getSession()->get(MAGIC_LOGIN_CODE_SESSION, '');
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $form['#cache']['max-age'] = 0;
    $form['#attributes']['class'][] = 'magic-login-code-form';
    $form['#attached']['library'][] = 'magic_login/forms';
    $email = $this->sessionEmail();
    $minutes = (int) round((int) ($this->config('magic_login.settings')->get('code_expiry') ?: 600) / 60);

    if ($email !== '') {
      $form['intro'] = [
        '#markup' => '<p class="magic-login-code-form__lead">' . $this->t('If %mail has an account, we’ve emailed it a 6-digit code. Type it below.', ['%mail' => $email]) . '</p>'
          . '<p class="magic-login-code-form__hint">' . $this->t('On a phone, the code may pop up above your keyboard. Tap it to fill it in. It works for @minutes minutes.', ['@minutes' => $minutes]) . '</p>',
      ];
    }
    else {
      $form['intro'] = [
        '#markup' => '<p class="magic-login-code-form__lead">' . $this->t('Type your email and the 6-digit code we sent you.') . '</p>',
      ];
      $form['mail'] = [
        '#type' => 'email',
        '#title' => $this->t('Email address'),
        '#attributes' => [
          'autocomplete' => 'email',
          'autocapitalize' => 'none',
          'autocorrect' => 'off',
          'spellcheck' => 'false',
        ],
      ];
    }

    // One real field, not six: the phone's "From Mail" suggestion and a paste
    // both fill a single field. js/magic_login_code.js draws the six digit
    // boxes over it. Room for a pasted sentence ("Your ... code is: 123456"),
    // which the script and verifyCode() both reduce to its digits.
    $form['code'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Sign-in code'),
      '#size' => 9,
      '#maxlength' => 128,
      '#attributes' => [
        // The keys to "From Mail" / "Found in email" suggestions.
        'autocomplete' => 'one-time-code',
        'inputmode' => 'numeric',
        'autocapitalize' => 'none',
        'autocorrect' => 'off',
        'spellcheck' => 'false',
        'placeholder' => '••••••',
        'class' => ['magic-login-code-form__code'],
        'data-magic-login-code' => (string) MagicLinkManagerInterface::CODE_LENGTH,
        'autofocus' => 'autofocus',
      ],
    ];

    $form['actions'] = ['#type' => 'actions'];
    $form['actions']['submit'] = [
      '#type' => 'submit',
      '#name' => 'magic_login_verify',
      '#value' => $this->t('Sign in'),
      '#button_type' => 'primary',
    ];

    // Alternatives, for a code that never came or a change of mind. They go
    // to the address in the session only, never one typed here.
    if ($email !== '') {
      $form['other'] = [
        '#type' => 'container',
        '#attributes' => ['class' => ['magic-login-code-form__other']],
        '#weight' => 110,
        'title' => [
          '#type' => 'html_tag',
          '#tag' => 'p',
          '#value' => $this->t('No code? Look in your spam folder, or:'),
        ],
        'resend' => [
          '#type' => 'submit',
          '#name' => 'magic_login_resend',
          '#value' => $this->t('Send a new code'),
          '#attributes' => ['class' => ['button--small']],
        ],
        'link' => [
          '#type' => 'submit',
          '#name' => 'magic_login_link_instead',
          '#value' => $this->t('Email me a sign-in link instead'),
          '#attributes' => ['class' => ['button--small']],
        ],
        'change' => [
          '#type' => 'link',
          '#title' => $this->t('Use a different email address'),
          '#url' => Url::fromRoute('user.login'),
          '#attributes' => ['class' => ['magic-login-code-form__change']],
        ],
      ];
    }

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    $button = $form_state->getTriggeringElement()['#name'] ?? '';
    if ($button !== 'magic_login_verify') {
      if ($this->sessionEmail() === '') {
        $form_state->setErrorByName('', $this->t('Please start again from the sign-in page.'));
      }
      return;
    }

    $email = $this->sessionEmail() ?: trim((string) $form_state->getValue('mail'));
    $code = (string) $form_state->getValue('code');
    if ($email === '') {
      $form_state->setErrorByName('mail', $this->t('Type the email address the code went to.'));
      return;
    }
    if (trim($code) === '') {
      $form_state->setErrorByName('code', $this->t('Type the 6-digit code from the email.'));
      return;
    }

    // A failed CAPTCHA (or any other error) stops here: no guess is made, so
    // a bot that has not passed the check cannot spend anyone's attempts.
    if ($form_state->hasAnyErrors()) {
      return;
    }
    $account = $this->linkManager->verifyCode($email, $code, $this->getRequest()->getClientIp());
    if (!$account instanceof UserInterface) {
      // One message for every failure: wrong, expired, used up, rate
      // limited, or no such account.
      $form_state->setErrorByName('code', $this->t('That code didn’t work. Check it and try again, or get a new one. Each code works once, for a few minutes.'));
      return;
    }
    $form_state->set('magic_login_account', $account);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $button = $form_state->getTriggeringElement()['#name'] ?? '';
    $email = $this->sessionEmail();

    if ($button === 'magic_login_resend') {
      magic_login_request_code($email);
      $this->messenger()->addStatus($this->t('If we know that email, we’ve sent a new code. Use the newest one.'));
      $form_state->setRedirect('magic_login.code');
      return;
    }
    if ($button === 'magic_login_link_instead') {
      $this->linkManager->requestLink($email, $this->getRequest()->getClientIp());
      $this->messenger()->addStatus($this->t('If we know that email, we’ve sent you a sign-in link. Check your email.'));
      $form_state->setRedirect('user.login');
      return;
    }

    /** @var \Drupal\user\UserInterface $account */
    $account = $form_state->get('magic_login_account');
    $this->getRequest()->getSession()->remove(MAGIC_LOGIN_CODE_SESSION);
    $form_state->setRedirectUrl(magic_login_complete_sign_in($account, 'a sign-in code'));
  }

}
