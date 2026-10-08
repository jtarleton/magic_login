<?php

declare(strict_types=1);

namespace Drupal\magic_login\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;
use Drupal\user\Entity\User;
use Drupal\user\UserInterface;

/**
 * Optional profile step after an account's first sign-in, at /welcome.
 */
final class MagicLoginWelcomeForm extends FormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'magic_login_welcome_form';
  }

  private function account(): ?UserInterface {
    $account = User::load($this->currentUser()->id());
    return $account instanceof UserInterface && $account->hasField('field_display_name') ? $account : NULL;
  }

  /**
   * {@inheritdoc}
   */
  /**
   * Title callback: "Welcome to [site name]".
   */
  public function title(): string {
    return (string) $this->t('Welcome to @site', ['@site' => (string) $this->config('system.site')->get('name')]);
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $form['#cache']['max-age'] = 0;
    $account = $this->account();

    $form['how'] = [
      '#markup' => '<p>' . $this->t('You are signed in. From now on, signing in always works this way: enter your email address and use the link or code we email you. There is no password, so there are no credentials to remember apart from your email address (@mail).', [
        '@mail' => $this->currentUser()->getEmail(),
      ]) . '</p>',
    ];

    if ($account) {
      $form['name'] = [
        '#type' => 'textfield',
        '#title' => $this->t('Your name (optional)'),
        '#description' => $this->t('What should we call you? You can change this later.'),
        '#maxlength' => 60,
        '#default_value' => $account->get('field_display_name')->value,
        '#attributes' => ['autocomplete' => 'name'],
      ];
    }

    $form['actions'] = ['#type' => 'actions'];
    if ($account) {
      $form['actions']['submit'] = [
        '#type' => 'submit',
        '#value' => $this->t('Save'),
        '#button_type' => 'primary',
      ];
    }
    $form['actions']['skip'] = [
      '#type' => 'link',
      '#title' => $account ? $this->t('Skip for now') : $this->t('Continue'),
      '#url' => magic_login_landing_url(),
      '#attributes' => ['class' => ['button']],
    ];

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $account = $this->account();
    if ($account) {
      $name = trim((string) $form_state->getValue('name'));
      $account->set('field_display_name', $name === '' ? NULL : $name);
      $account->save();
      if ($name !== '') {
        $this->messenger()->addStatus($this->t('Thanks, @name.', ['@name' => $name]));
      }
    }
    $form_state->setRedirectUrl(magic_login_landing_url());
  }

}
