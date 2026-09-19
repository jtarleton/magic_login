<?php

declare(strict_types=1);

namespace Drupal\magic_login\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;
use Drupal\magic_login\MagicLinkManagerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Standalone "email me a sign-in link" form at /user/login/link.
 */
final class MagicLoginRequestForm extends FormBase {

  public function __construct(
    private readonly MagicLinkManagerInterface $linkManager,
    private readonly RequestStack $requestStack,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): self {
    return new self(
      $container->get('magic_login.link_manager'),
      $container->get('request_stack'),
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
      '#markup' => '<p>' . $this->t('Enter your email address and we will send you a link that signs you in. No password needed.') . '</p>',
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

    $form['actions'] = ['#type' => 'actions'];
    $form['actions']['submit'] = [
      '#type' => 'submit',
      '#value' => $this->t('Email me a sign-in link'),
      '#button_type' => 'primary',
    ];

    $form['password_login'] = [
      '#type' => 'link',
      '#title' => $this->t('Sign in with a password instead'),
      '#url' => Url::fromRoute('user.login'),
      '#prefix' => '<p>',
      '#suffix' => '</p>',
    ];

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $ip = $this->requestStack->getCurrentRequest()?->getClientIp();
    $this->linkManager->requestLink((string) $form_state->getValue('mail'), $ip);

    // One message for every outcome. Branching here -- "no account with that
    // address", "you're doing that too often" -- hands an attacker a list of
    // which addresses are registered.
    $this->messenger()->addStatus($this->t('If that address belongs to an account, a sign-in link is on its way. Check your inbox.'));

    $form_state->setRedirect('user.login');
  }

}
