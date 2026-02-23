<?php

declare(strict_types=1);

namespace Drupal\webauthn\Form;

use Drupal\Core\Access\CsrfTokenGenerator;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Datetime\DateFormatterInterface;
use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\webauthn\Service\TotpManager;
use Drupal\webauthn\Service\WebAuthnManager;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * 2FA/MFA verification form displayed after password login.
 */
class WebAuthnVerifyForm extends FormBase {

  /**
   * The CSRF token generator.
   *
   * @var \Drupal\Core\Access\CsrfTokenGenerator
   */
  protected CsrfTokenGenerator $csrfToken;

  /**
   * The current user.
   *
   * @var \Drupal\Core\Session\AccountProxyInterface
   */
  protected AccountProxyInterface $account;

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected ConfigFactoryInterface $configFactory;

  /**
   * The WebAuthn manager service.
   *
   * @var \Drupal\webauthn\Service\WebAuthnManager
   */
  protected WebAuthnManager $webauthnManager;

  /**
   * The TOTP manager service.
   *
   * @var \Drupal\webauthn\Service\TotpManager
   */
  protected TotpManager $totpManager;

  /**
   * The request stack.
   *
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  protected RequestStack $requestStack;

  /**
   * The date formatter service.
   *
   * @var \Drupal\Core\Datetime\DateFormatterInterface
   */
  protected DateFormatterInterface $dateFormatter;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    $instance = new static();
    $instance->csrfToken = $container->get('csrf_token');
    $instance->account = $container->get('current_user');
    $instance->configFactory = $container->get('config.factory');
    $instance->webauthnManager = $container->get('webauthn.manager');
    $instance->totpManager = $container->get('webauthn.totp_manager');
    $instance->requestStack = $container->get('request_stack');
    $instance->dateFormatter = $container->get('date.formatter');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'webauthn_verify_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $uid = (int) $this->account->id();
    $config = $this->configFactory->get('webauthn.settings');

    $has_webauthn = $this->webauthnManager->userHasCredentials($uid);
    $has_totp = $this->totpManager->userHasTotp($uid);
    $verification_mode = $config->get('verification_mode') ?: 'any';

    // Check which steps are already completed (for page refresh during MFA).
    $request = $this->requestStack->getCurrentRequest();
    $session = $request?->getSession();
    $completed = $session ? $session->get('webauthn_mfa_completed', []) : [];

    $settings = [
      'mode' => 'verify',
      'hasWebauthn' => $has_webauthn,
      'hasTotp' => $has_totp,
      'verificationMode' => $verification_mode,
      'completedMethods' => array_values($completed),
    ];

    if ($has_webauthn) {
      $settings['assertOptionsUrl'] = '/webauthn/assert-options?token=' . $this->csrfToken->get('webauthn/assert-options');
      $settings['assertVerifyUrl'] = '/webauthn/assert-verify?token=' . $this->csrfToken->get('webauthn/assert-verify');
    }

    if ($has_totp) {
      $settings['totpVerifyUrl'] = '/webauthn/totp-verify?token=' . $this->csrfToken->get('webauthn/totp-verify');
    }

    $form['#theme'] = 'webauthn_verify';
    $form['#login_ip'] = $request?->getClientIp() ?? '';
    $form['#prev_login_ip'] = $session ? $session->get('webauthn_prev_login_ip') : '';
    $prev_time = $session ? $session->get('webauthn_prev_login_time') : 0;
    $form['#prev_login_time'] = $prev_time ? $this->dateFormatter->format($prev_time, 'medium') : '';
    $form['#cache'] = ['max-age' => 0];
    $form['#attached']['library'][] = 'webauthn/webauthn';
    $form['#attached']['drupalSettings']['webauthn'] = $settings;

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    // Form submission is handled via AJAX in the controller.
  }

}
