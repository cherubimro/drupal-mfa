<?php

declare(strict_types=1);

namespace Drupal\webauthn\PageCache;

use Drupal\Core\PageCache\RequestPolicyInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Denies dynamic page caching while a session still owes a second factor.
 *
 * Dynamic Page Cache runs after the 2FA gate and can serve a stored page
 * without rebuilding it, which would bypass the block restrictions applied
 * to pending sessions.
 */
class DenyPendingTwoFactor implements RequestPolicyInterface {

  /**
   * The current user.
   *
   * @var \Drupal\Core\Session\AccountProxyInterface
   */
  protected AccountProxyInterface $currentUser;

  /**
   * Constructs the policy.
   *
   * @param \Drupal\Core\Session\AccountProxyInterface $current_user
   *   The current user.
   */
  public function __construct(AccountProxyInterface $current_user) {
    $this->currentUser = $current_user;
  }

  /**
   * {@inheritdoc}
   */
  public function check(Request $request) {
    if (!$request->hasSession() || $this->currentUser->isAnonymous()) {
      return NULL;
    }
    $session = $request->getSession();
    $uid = (int) $this->currentUser->id();
    if ($session->get('webauthn_2fa_pending')
      && (int) $session->get('uid') === $uid
      && $session->get('webauthn_2fa_ok') !== $uid) {
      return static::DENY;
    }
    return NULL;
  }

}
