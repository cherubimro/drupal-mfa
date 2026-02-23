<?php

declare(strict_types=1);

namespace Drupal\webauthn\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * Admin configuration form for WebAuthn 2FA settings.
 */
class WebAuthnAdminSettingsForm extends ConfigFormBase {

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames(): array {
    return ['webauthn.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'webauthn_admin_settings_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config('webauthn.settings');

    $form['policy'] = [
      '#type' => 'select',
      '#title' => $this->t('2FA Policy'),
      '#options' => [
        'disabled' => $this->t('Disabled'),
        'optional' => $this->t('Optional (users choose)'),
        'required' => $this->t('Required (all users with keys)'),
      ],
      '#default_value' => $config->get('policy') ?: 'optional',
      '#description' => $this->t('Controls whether 2FA is enforced site-wide.'),
    ];

    $form['verification_mode'] = [
      '#type' => 'select',
      '#title' => $this->t('Verification Mode'),
      '#options' => [
        'any' => $this->t('Any single method (2FA)'),
        'all' => $this->t('All configured methods (MFA)'),
      ],
      '#default_value' => $config->get('verification_mode') ?: 'any',
      '#description' => $this->t('"Any" lets users verify with one method (security key or authenticator app). "All" requires every configured method — when a user has both a security key and an authenticator app, they must use both to log in.'),
    ];

    $form['rp_name'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Relying Party Name'),
      '#default_value' => $config->get('rp_name'),
      '#description' => $this->t('Display name shown in authenticator prompts. Defaults to site name if empty.'),
    ];

    $form['rp_id'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Relying Party ID'),
      '#default_value' => $config->get('rp_id'),
      '#description' => $this->t('Domain name (e.g. "example.com"). Defaults to current host if empty. Must match the domain users access the site from.'),
    ];

    $form['timeout'] = [
      '#type' => 'number',
      '#title' => $this->t('Ceremony Timeout (ms)'),
      '#default_value' => $config->get('timeout') ?: 60000,
      '#min' => 15000,
      '#max' => 300000,
      '#description' => $this->t('How long users have to complete a WebAuthn ceremony, in milliseconds.'),
    ];

    $form['user_verification'] = [
      '#type' => 'select',
      '#title' => $this->t('User Verification'),
      '#options' => [
        'preferred' => $this->t('Preferred'),
        'required' => $this->t('Required'),
        'discouraged' => $this->t('Discouraged'),
      ],
      '#default_value' => $config->get('user_verification') ?: 'preferred',
      '#description' => $this->t('Whether to require biometric/PIN verification on the authenticator.'),
    ];

    $form['attestation'] = [
      '#type' => 'select',
      '#title' => $this->t('Attestation Conveyance'),
      '#options' => [
        'none' => $this->t('None'),
        'indirect' => $this->t('Indirect'),
        'direct' => $this->t('Direct'),
      ],
      '#default_value' => $config->get('attestation') ?: 'none',
      '#description' => $this->t('Whether to request attestation from authenticators. "None" is recommended for most sites.'),
    ];

    $form['attachment'] = [
      '#type' => 'select',
      '#title' => $this->t('Authenticator Attachment'),
      '#options' => [
        '' => $this->t('Any'),
        'platform' => $this->t('Platform (built-in biometric)'),
        'cross-platform' => $this->t('Cross-platform (USB/NFC key)'),
      ],
      '#default_value' => $config->get('attachment') ?: '',
      '#description' => $this->t('Restrict the type of authenticator that can be registered.'),
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $this->config('webauthn.settings')
      ->set('policy', $form_state->getValue('policy'))
      ->set('verification_mode', $form_state->getValue('verification_mode'))
      ->set('rp_name', $form_state->getValue('rp_name'))
      ->set('rp_id', $form_state->getValue('rp_id'))
      ->set('timeout', (int) $form_state->getValue('timeout'))
      ->set('user_verification', $form_state->getValue('user_verification'))
      ->set('attestation', $form_state->getValue('attestation'))
      ->set('attachment', $form_state->getValue('attachment'))
      ->save();

    parent::submitForm($form, $form_state);
  }

}
