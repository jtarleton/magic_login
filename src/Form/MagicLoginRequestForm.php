<?php

declare(strict_types=1);

namespace Drupal\magic_login\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\magic_login\MagicLinkManagerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Standalone "email me a sign-in link" form at /user/login/link.
 */
final class MagicLoginRequestForm extends FormBase {

  public function __construct(
    protected MagicLinkManagerInterface $linkManager,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): self {
    return new self(
      $container->get('magic_login.link_manager'),
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'magic_login_request_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $form['#cache']['max-age'] = 0;

    $form['intro'] = [
      '#markup' => '<p>' . $this->t('Type your email. We’ll send you a link or a 6-digit code to sign in. No password needed.') . '</p>',
    ];

    $form['mail'] = [
      '#type' => 'email',
      '#title' => $this->t('Email address'),
      '#required' => TRUE,
      '#attributes' => [
        'autocomplete' => 'email',
        'autocapitalize' => 'none',
        'autocorrect' => 'off',
        'spellcheck' => 'false',
      ],
    ];

    $form['approval'] = magic_login_approval_notice();

    $form['actions'] = ['#type' => 'actions'];
    $form['actions']['methods'] = magic_login_method_buttons((string) $this->t('Email me a sign-in link'));
    $form['#attached']['library'][] = 'magic_login/forms';

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    if (magic_login_code_pressed($form_state)) {
      magic_login_request_code((string) $form_state->getValue('mail'));
      $form_state->setRedirect('magic_login.code');
      return;
    }
    $ip = $this->getRequest()->getClientIp();
    $this->linkManager->requestLink((string) $form_state->getValue('mail'), $ip);

    // One message for every outcome. Branching here -- "no account with that
    // address", "you're doing that too often" -- hands an attacker a list of
    // which addresses are registered.
    $this->messenger()->addStatus($this->t('If we know that email, we’ve sent you a sign-in link. Check your email.'));

    $form_state->setRedirect('user.login');
  }

}
