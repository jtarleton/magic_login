<?php

declare(strict_types=1);

namespace Drupal\magic_login\Form;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\TypedConfigManagerInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Configuration form for Magic Login.
 */
final class SettingsForm extends ConfigFormBase {

  public function __construct(
    ConfigFactoryInterface $config_factory,
    TypedConfigManagerInterface $typed_config_manager,
    private readonly EntityTypeManagerInterface $entityTypeManager,
  ) {
    parent::__construct($config_factory, $typed_config_manager);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): self {
    return new self(
      $container->get('config.factory'),
      $container->get('config.typed'),
      $container->get('entity_type.manager'),
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'magic_login_settings_form';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames(): array {
    return ['magic_login.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config('magic_login.settings');

    $form['link_expiry'] = [
      '#type' => 'number',
      '#title' => $this->t('Link expiry'),
      '#field_suffix' => $this->t('seconds'),
      '#min' => 60,
      '#max' => 86400,
      '#default_value' => $config->get('link_expiry'),
      '#required' => TRUE,
      '#description' => $this->t('How long a link stays valid. Links are also retired by any successful login or password change on the account, so this is an upper bound, not the usual lifetime.'),
    ];

    $form['login_form_integration'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Add a sign-in link option to the main login form'),
      '#default_value' => $config->get('login_form_integration'),
      '#description' => $this->t('Leave this off to keep /user/login untouched and link people to /user/login/link yourself.'),
    ];

    $form['registration'] = [
      '#type' => 'details',
      '#title' => $this->t('Account creation'),
      '#open' => TRUE,
    ];

    $form['registration']['auto_register'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Create an account when an unrecognised address requests a link'),
      '#default_value' => $config->get('auto_register'),
      '#description' => $this->t('This bypasses the "Who can register accounts?" setting on the <a href=":url">account settings</a> page by design: it is what removes the signup step. Anyone who can receive mail at an address permitted below gets an account.', [
        ':url' => '/admin/config/people/accounts',
      ]),
    ];

    $form['registration']['auto_register_roles'] = [
      '#type' => 'checkboxes',
      '#title' => $this->t('Roles for auto-created accounts'),
      '#options' => $this->roleOptions(),
      '#default_value' => (array) $config->get('auto_register_roles'),
      '#states' => [
        'visible' => [':input[name="auto_register"]' => ['checked' => TRUE]],
      ],
    ];

    $form['registration']['allowed_domains'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Allowed email domains'),
      '#rows' => 3,
      '#default_value' => $config->get('allowed_domains'),
      '#description' => $this->t('One per line or comma-separated. Leave empty to allow any domain. Applies to account creation only; existing accounts can always request a link.'),
      '#states' => [
        'visible' => [':input[name="auto_register"]' => ['checked' => TRUE]],
      ],
    ];

    $form['registration']['blocked_domains'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Blocked email domains'),
      '#rows' => 3,
      '#default_value' => $config->get('blocked_domains'),
      '#description' => $this->t('Checked before the allow list. Useful for disposable-address providers.'),
      '#states' => [
        'visible' => [':input[name="auto_register"]' => ['checked' => TRUE]],
      ],
    ];

    $form['limits'] = [
      '#type' => 'details',
      '#title' => $this->t('Rate limits'),
      '#open' => TRUE,
      '#description' => $this->t('Without these, this form is an open relay for sending mail to arbitrary addresses. Keep them tight.'),
    ];

    $form['limits']['flood_email_limit'] = [
      '#type' => 'number',
      '#title' => $this->t('Requests per email address'),
      '#min' => 1,
      '#default_value' => $config->get('flood_email_limit'),
      '#required' => TRUE,
    ];

    $form['limits']['flood_email_window'] = [
      '#type' => 'number',
      '#title' => $this->t('Email window'),
      '#field_suffix' => $this->t('seconds'),
      '#min' => 60,
      '#default_value' => $config->get('flood_email_window'),
      '#required' => TRUE,
    ];

    $form['limits']['flood_ip_limit'] = [
      '#type' => 'number',
      '#title' => $this->t('Requests per IP address'),
      '#min' => 1,
      '#default_value' => $config->get('flood_ip_limit'),
      '#required' => TRUE,
    ];

    $form['limits']['flood_ip_window'] = [
      '#type' => 'number',
      '#title' => $this->t('IP window'),
      '#field_suffix' => $this->t('seconds'),
      '#min' => 60,
      '#default_value' => $config->get('flood_ip_window'),
      '#required' => TRUE,
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $roles = array_values(array_filter((array) $form_state->getValue('auto_register_roles')));

    $this->config('magic_login.settings')
      ->set('link_expiry', (int) $form_state->getValue('link_expiry'))
      ->set('login_form_integration', (bool) $form_state->getValue('login_form_integration'))
      ->set('auto_register', (bool) $form_state->getValue('auto_register'))
      ->set('auto_register_roles', $roles)
      ->set('allowed_domains', (string) $form_state->getValue('allowed_domains'))
      ->set('blocked_domains', (string) $form_state->getValue('blocked_domains'))
      ->set('flood_email_limit', (int) $form_state->getValue('flood_email_limit'))
      ->set('flood_email_window', (int) $form_state->getValue('flood_email_window'))
      ->set('flood_ip_limit', (int) $form_state->getValue('flood_ip_limit'))
      ->set('flood_ip_window', (int) $form_state->getValue('flood_ip_window'))
      ->save();

    parent::submitForm($form, $form_state);
  }

  /**
   * Builds the role checkbox options, minus the two core pseudo-roles.
   *
   * @return array<string, string>
   *   Role labels keyed by role ID.
   */
  private function roleOptions(): array {
    $options = [];

    foreach ($this->entityTypeManager->getStorage('user_role')->loadMultiple() as $rid => $role) {
      if (in_array($rid, ['anonymous', 'authenticated'], TRUE)) {
        continue;
      }
      $options[$rid] = $role->label();
    }

    return $options;
  }

}
