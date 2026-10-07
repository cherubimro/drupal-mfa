<?php

declare(strict_types=1);

namespace Drupal\webauthn\Controller;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Access\CsrfTokenGenerator;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Datetime\DateFormatterInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\user\UserDataInterface;
use Drupal\user\UserInterface;
use Drupal\webauthn\Service\TotpManager;
use Drupal\webauthn\Service\WebAuthnManager;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * User "Security Keys" settings tab.
 */
class WebAuthnUserSettingsController extends ControllerBase {

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
   * The user data service.
   *
   * @var \Drupal\user\UserDataInterface
   */
  protected UserDataInterface $userData;

  /**
   * The date formatter service.
   *
   * @var \Drupal\Core\Datetime\DateFormatterInterface
   */
  protected DateFormatterInterface $dateFormatter;

  /**
   * The CSRF token generator.
   *
   * @var \Drupal\Core\Access\CsrfTokenGenerator
   */
  protected CsrfTokenGenerator $csrfToken;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    $instance = parent::create($container);
    $instance->webauthnManager = $container->get('webauthn.manager');
    $instance->totpManager = $container->get('webauthn.totp_manager');
    $instance->userData = $container->get('user.data');
    $instance->dateFormatter = $container->get('date.formatter');
    $instance->csrfToken = $container->get('csrf_token');
    $instance->configFactory = $container->get('config.factory');
    return $instance;
  }

  /**
   * Renders the security keys management page for a user.
   *
   * @param \Drupal\user\UserInterface $user
   *   The user whose keys to manage.
   *
   * @return array
   *   A render array.
   */
  public function page(UserInterface $user): array {
    $uid = (int) $user->id();
    $credentials = $this->webauthnManager->getCredentials($uid);

    $tfa_enabled = !empty($this->userData->get('webauthn', $uid, '2fa_enabled'));
    $has_totp = $this->totpManager->userHasTotp($uid);

    $rows = [];
    foreach ($credentials as $cred) {
      $rows[] = [
        'id' => $cred->id,
        'description' => $cred->description ?: $this->t('Unnamed key'),
        'created' => $this->dateFormatter->format($cred->created, 'short'),
        'last_used' => $cred->last_used ? $this->dateFormatter->format($cred->last_used, 'short') : $this->t('Never'),
        'clone_warning' => (bool) $cred->clone_warning,
      ];
    }

    // Generate CSRF tokens manually — Url::fromRoute()->toString() inside a
    // render context inserts placeholder hashes instead of actual tokens.
    $build = [
      '#theme' => 'webauthn_user_settings',
      '#credentials' => $rows,
      '#tfa_enabled' => $tfa_enabled,
      '#has_totp' => $has_totp,
      // Disable render cache — CSRF tokens are per-session.
      '#cache' => ['max-age' => 0],
      '#attached' => [
        'library' => ['webauthn/webauthn'],
        'drupalSettings' => [
          'webauthn' => [
            'mode' => 'settings',
            'registerOptionsUrl' => '/webauthn/register-options?token=' . $this->csrfToken->get('webauthn/register-options'),
            'registerVerifyUrl' => '/webauthn/register-verify?token=' . $this->csrfToken->get('webauthn/register-verify'),
            'deleteUrl' => '/webauthn/delete?token=' . $this->csrfToken->get('webauthn/delete'),
            'toggleUrl' => '/webauthn/toggle?token=' . $this->csrfToken->get('webauthn/toggle'),
            'totpSetupUrl' => '/webauthn/totp-setup?token=' . $this->csrfToken->get('webauthn/totp-setup'),
            'totpConfirmUrl' => '/webauthn/totp-confirm?token=' . $this->csrfToken->get('webauthn/totp-confirm'),
            'totpRemoveUrl' => '/webauthn/totp-remove?token=' . $this->csrfToken->get('webauthn/totp-remove'),
            'credentials' => $rows,
            'tfaEnabled' => $tfa_enabled,
            'hasTotp' => $has_totp,
            'policy' => $this->configFactory->get('webauthn.settings')->get('policy') ?: 'optional',
          ],
        ],
      ],
    ];

    return $build;
  }

  /**
   * Title callback for the security keys page.
   *
   * @param \Drupal\user\UserInterface $user
   *   The user whose page title to generate.
   *
   * @return \Drupal\Core\StringTranslation\TranslatableMarkup
   *   The page title.
   */
  public function title(UserInterface $user): TranslatableMarkup {
    return $this->t('Security Keys');
  }

  /**
   * Access check: user can manage own keys, or admin can manage anyone's.
   *
   * @param \Drupal\user\UserInterface $user
   *   The user whose keys are being accessed.
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The current logged-in user.
   *
   * @return \Drupal\Core\Access\AccessResultInterface
   *   The access result.
   */
  public function access(UserInterface $user, AccountInterface $account): AccessResultInterface {
    if ($account->hasPermission('administer webauthn')) {
      return AccessResult::allowed();
    }
    if ($account->id() == $user->id() && $account->hasPermission('manage own security keys')) {
      return AccessResult::allowed()->cachePerUser();
    }
    return AccessResult::forbidden();
  }

}
