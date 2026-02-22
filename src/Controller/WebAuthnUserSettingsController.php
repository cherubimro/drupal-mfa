<?php

namespace Drupal\webauthn\Controller;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Url;
use Drupal\user\UserInterface;

/**
 * User "Security Keys" settings tab.
 */
class WebAuthnUserSettingsController extends ControllerBase {

  /**
   * Renders the security keys management page for a user.
   */
  public function page(UserInterface $user) {
    $uid = $user->id();
    /** @var \Drupal\webauthn\Service\WebAuthnManager $manager */
    $manager = \Drupal::service('webauthn.manager');
    /** @var \Drupal\webauthn\Service\TotpManager $totp_manager */
    $totp_manager = \Drupal::service('webauthn.totp_manager');
    $credentials = $manager->getCredentials($uid);

    $user_data = \Drupal::service('user.data');
    $tfa_enabled = !empty($user_data->get('webauthn', $uid, '2fa_enabled'));
    $has_totp = $totp_manager->userHasTotp($uid);

    $rows = [];
    foreach ($credentials as $cred) {
      $rows[] = [
        'id' => $cred->id,
        'description' => $cred->description ?: $this->t('Unnamed key'),
        'created' => \Drupal::service('date.formatter')->format($cred->created, 'short'),
        'last_used' => $cred->last_used ? \Drupal::service('date.formatter')->format($cred->last_used, 'short') : $this->t('Never'),
        'clone_warning' => (bool) $cred->clone_warning,
      ];
    }

    // Generate CSRF tokens manually — Url::fromRoute()->toString() inside a
    // render context inserts placeholder hashes instead of actual tokens.
    $csrf = \Drupal::csrfToken();
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
            'registerOptionsUrl' => '/webauthn/register-options?token=' . $csrf->get('webauthn/register-options'),
            'registerVerifyUrl' => '/webauthn/register-verify?token=' . $csrf->get('webauthn/register-verify'),
            'deleteUrl' => '/webauthn/delete?token=' . $csrf->get('webauthn/delete'),
            'toggleUrl' => '/webauthn/toggle?token=' . $csrf->get('webauthn/toggle'),
            'totpSetupUrl' => '/webauthn/totp-setup?token=' . $csrf->get('webauthn/totp-setup'),
            'totpConfirmUrl' => '/webauthn/totp-confirm?token=' . $csrf->get('webauthn/totp-confirm'),
            'totpRemoveUrl' => '/webauthn/totp-remove?token=' . $csrf->get('webauthn/totp-remove'),
            'credentials' => $rows,
            'tfaEnabled' => $tfa_enabled,
            'hasTotp' => $has_totp,
            'policy' => \Drupal::config('webauthn.settings')->get('policy') ?: 'optional',
          ],
        ],
      ],
    ];

    return $build;
  }

  /**
   * Title callback for the security keys page.
   */
  public function title(UserInterface $user) {
    return $this->t('Security Keys');
  }

  /**
   * Access check: user can manage own keys, or admin can manage anyone's.
   */
  public function access(UserInterface $user, AccountInterface $account) {
    if ($account->hasPermission('administer webauthn')) {
      return AccessResult::allowed();
    }
    if ($account->id() == $user->id() && $account->hasPermission('manage own security keys')) {
      return AccessResult::allowed()->cachePerUser();
    }
    return AccessResult::forbidden();
  }

}
