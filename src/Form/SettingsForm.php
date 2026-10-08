<?php

declare(strict_types=1);

namespace Drupal\magic_login\Form;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\TypedConfigManagerInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\magic_login\MagicLinkManager;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Configuration form for Magic Login.
 */
final class SettingsForm extends ConfigFormBase {

  public function __construct(
    ConfigFactoryInterface $config_factory,
    TypedConfigManagerInterface $typed_config_manager,
    protected EntityTypeManagerInterface $entityTypeManager,
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

    $form['landing_path'] = [
      '#type' => 'textfield',
      '#title' => $this->t('After signing in, go to'),
      '#default_value' => $config->get('landing_path') ?? '/',
      '#required' => TRUE,
      '#description' => $this->t('An internal path, such as / or /dashboard. The first sign-in shows the welcome step first.'),
    ];

    $form['code_expiry'] = [
      '#type' => 'number',
      '#title' => $this->t('Code expiry'),
      '#field_suffix' => $this->t('seconds'),
      '#min' => 60,
      '#max' => 3600,
      '#default_value' => $config->get('code_expiry') ?? 600,
      '#required' => TRUE,
      '#description' => $this->t('How long an emailed 6-digit sign-in code stays valid. Codes are also retired when used, by any sign-in, and after too many wrong tries.'),
    ];

    $form['code_max_attempts'] = [
      '#type' => 'number',
      '#title' => $this->t('Wrong tries per code'),
      '#min' => 1,
      '#max' => 10,
      '#default_value' => $config->get('code_max_attempts') ?? 5,
      '#required' => TRUE,
      '#description' => $this->t('After this many wrong tries the code is discarded and a new one must be requested.'),
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
      '#title' => $this->t('Create an account when an unrecognized address requests a link'),
      '#default_value' => $config->get('auto_register'),
      '#description' => $this->t('This bypasses the "Who can register accounts?" setting on the <a href=":url">account settings</a> page by design: it is what removes the signup step. Anyone who can receive mail at an address permitted below gets an account.', [
        ':url' => '/admin/config/people/accounts',
      ]),
    ];

    $form['registration']['public_signup'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Open the public sign-up form'),
      '#default_value' => $config->get('public_signup'),
      '#description' => $this->t('The <a href=":url">sign-up page</a> creates an account the first time a new address signs in. While this is off, the page is visible but its button is disabled. The domain lists below still apply.', [
        ':url' => '/signin',
      ]),
    ];

    $form['registration']['require_approval'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('New accounts wait for administrator approval'),
      '#default_value' => $config->get('require_approval') ?? TRUE,
      '#description' => $this->t('Off: a new account is active immediately and its first sign-in link is emailed straight away. Clicking that link is what proves the address.'),
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

    $form['registration']['signup_role_permissions'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Permissions a sign-up role may have'),
      '#rows' => 3,
      '#default_value' => implode("\n", (array) $config->get('signup_role_permissions')),
      '#description' => $this->t('One permission machine name per line (e.g. "access content"). A role is only ever given to a self-created account if it is not an admin role and has no permission outside this list; empty means the role may have no permissions at all.'),
    ];

    $form['registration']['signup_role_excluded'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Roles never given to self-created accounts'),
      '#default_value' => implode(', ', (array) $config->get('signup_role_excluded')),
      '#description' => $this->t('Role machine names, comma-separated: e.g. a role granted only on payment.'),
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

    $form['limits']['flood_verify_ip_limit'] = [
      '#type' => 'number',
      '#title' => $this->t('Code attempts per IP address'),
      '#min' => 1,
      '#default_value' => $config->get('flood_verify_ip_limit') ?? 30,
      '#required' => TRUE,
    ];

    $form['limits']['flood_verify_email_limit'] = [
      '#type' => 'number',
      '#title' => $this->t('Code attempts per email address'),
      '#min' => 1,
      '#default_value' => $config->get('flood_verify_email_limit') ?? 10,
      '#required' => TRUE,
    ];

    $form['limits']['flood_verify_window'] = [
      '#type' => 'number',
      '#title' => $this->t('Code attempt window'),
      '#field_suffix' => $this->t('seconds'),
      '#min' => 60,
      '#default_value' => $config->get('flood_verify_window') ?? 3600,
      '#required' => TRUE,
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    $path = trim((string) $form_state->getValue('landing_path'));
    if ($path === '' || $path[0] !== '/' || str_starts_with($path, '//')) {
      $form_state->setErrorByName('landing_path', $this->t('Enter an internal path starting with /.'));
    }
    parent::validateForm($form, $form_state);
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
      ->set('public_signup', (bool) $form_state->getValue('public_signup'))
      ->set('require_approval', (bool) $form_state->getValue('require_approval'))
      ->set('auto_register_roles', $roles)
      ->set('landing_path', trim((string) $form_state->getValue('landing_path')))
      ->set('signup_role_permissions', array_values(array_filter(array_map('trim', preg_split('/[\r\n]+/', (string) $form_state->getValue('signup_role_permissions')) ?: []))))
      ->set('signup_role_excluded', array_values(array_filter(array_map('trim', explode(',', (string) $form_state->getValue('signup_role_excluded'))))))
      ->set('allowed_domains', (string) $form_state->getValue('allowed_domains'))
      ->set('blocked_domains', (string) $form_state->getValue('blocked_domains'))
      ->set('flood_email_limit', (int) $form_state->getValue('flood_email_limit'))
      ->set('flood_email_window', (int) $form_state->getValue('flood_email_window'))
      ->set('flood_ip_limit', (int) $form_state->getValue('flood_ip_limit'))
      ->set('flood_ip_window', (int) $form_state->getValue('flood_ip_window'))
      ->set('code_expiry', (int) $form_state->getValue('code_expiry'))
      ->set('code_max_attempts', (int) $form_state->getValue('code_max_attempts'))
      ->set('flood_verify_ip_limit', (int) $form_state->getValue('flood_verify_ip_limit'))
      ->set('flood_verify_email_limit', (int) $form_state->getValue('flood_verify_email_limit'))
      ->set('flood_verify_window', (int) $form_state->getValue('flood_verify_window'))
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
      // Only roles a self-created account may safely get; see
      // MagicLinkManager::isSafeSignupRole().
      if (!MagicLinkManager::isSafeSignupRole($rid)) {
        continue;
      }
      $options[$rid] = $role->label();
    }

    return $options;
  }

}
