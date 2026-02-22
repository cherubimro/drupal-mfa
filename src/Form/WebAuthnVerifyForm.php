<?php

namespace Drupal\webauthn\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;

/**
 * 2FA/MFA verification form displayed after password login.
 */
class WebAuthnVerifyForm extends FormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'webauthn_verify_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $csrf = \Drupal::csrfToken();
    $uid = \Drupal::currentUser()->id();
    $config = \Drupal::config('webauthn.settings');

    /** @var \Drupal\webauthn\Service\WebAuthnManager $manager */
    $manager = \Drupal::service('webauthn.manager');
    /** @var \Drupal\webauthn\Service\TotpManager $totp_manager */
    $totp_manager = \Drupal::service('webauthn.totp_manager');

    $has_webauthn = $manager->userHasCredentials($uid);
    $has_totp = $totp_manager->userHasTotp($uid);
    $verification_mode = $config->get('verification_mode') ?: 'any';

    // Check which steps are already completed (for page refresh during MFA).
    $session = \Drupal::request()->getSession();
    $completed = $session ? $session->get('webauthn_mfa_completed', []) : [];

    $settings = [
      'mode' => 'verify',
      'hasWebauthn' => $has_webauthn,
      'hasTotp' => $has_totp,
      'verificationMode' => $verification_mode,
      'completedMethods' => array_values($completed),
    ];

    if ($has_webauthn) {
      $settings['assertOptionsUrl'] = '/webauthn/assert-options?token=' . $csrf->get('webauthn/assert-options');
      $settings['assertVerifyUrl'] = '/webauthn/assert-verify?token=' . $csrf->get('webauthn/assert-verify');
    }

    if ($has_totp) {
      $settings['totpVerifyUrl'] = '/webauthn/totp-verify?token=' . $csrf->get('webauthn/totp-verify');
    }

    $form['#theme'] = 'webauthn_verify';
    $form['#login_ip'] = \Drupal::request()->getClientIp();
    $form['#prev_login_ip'] = $session ? $session->get('webauthn_prev_login_ip') : '';
    $prev_time = $session ? $session->get('webauthn_prev_login_time') : 0;
    $form['#prev_login_time'] = $prev_time ? \Drupal::service('date.formatter')->format($prev_time, 'medium') : '';
    $form['#cache'] = ['max-age' => 0];
    $form['#attached']['library'][] = 'webauthn/webauthn';
    $form['#attached']['drupalSettings']['webauthn'] = $settings;

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    // Form submission is handled via AJAX in the controller.
  }

}
