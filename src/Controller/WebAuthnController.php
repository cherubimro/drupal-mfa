<?php

declare(strict_types=1);

namespace Drupal\webauthn\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Url;
use Drupal\user\UserDataInterface;
use Drupal\webauthn\Service\TotpManager;
use Drupal\webauthn\Service\WebAuthnManager;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * AJAX endpoints for WebAuthn and TOTP ceremony operations.
 */
class WebAuthnController extends ControllerBase {

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
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    $instance = parent::create($container);
    $instance->webauthnManager = $container->get('webauthn.manager');
    $instance->totpManager = $container->get('webauthn.totp_manager');
    $instance->userData = $container->get('user.data');
    return $instance;
  }

  /**
   * Returns assertion options (challenge) for 2FA verification.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response with assertion options or error.
   */
  public function assertOptions(Request $request): JsonResponse {
    try {
      $uid = (int) $this->currentUser()->id();
      $result = $this->webauthnManager->beginAssertion($uid);

      // Store challenge in session.
      $session = $request->getSession();
      $session->set('webauthn_challenge', $result['challenge']);

      return new JsonResponse([
        'success' => TRUE,
        'options' => $result['args'],
      ]);
    }
    catch (\Exception $e) {
      return new JsonResponse([
        'success' => FALSE,
        'error' => $e->getMessage(),
      ], 400);
    }
  }

  /**
   * Verifies an assertion response for 2FA.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response with verification result.
   */
  public function assertVerify(Request $request): JsonResponse {
    try {
      $uid = (int) $this->currentUser()->id();
      $session = $request->getSession();
      $challenge = $session->get('webauthn_challenge');

      if (!$challenge) {
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'No challenge found in session.',
        ], 400);
      }

      $content = json_decode($request->getContent(), TRUE);
      if (!$content) {
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Invalid request body.',
        ], 400);
      }

      $success = $this->webauthnManager->finishAssertion(
        $uid,
        $challenge,
        $content['credentialId'] ?? '',
        $content['clientDataJSON'] ?? '',
        $content['authenticatorData'] ?? '',
        $content['signature'] ?? ''
      );

      // Clear challenge.
      $session->remove('webauthn_challenge');

      if ($success) {
        return $this->complete2fa($session, $uid, 'webauthn');
      }

      return new JsonResponse([
        'success' => FALSE,
        'error' => 'Verification failed.',
      ], 400);
    }
    catch (\Exception $e) {
      return new JsonResponse([
        'success' => FALSE,
        'error' => $e->getMessage(),
      ], 400);
    }
  }

  /**
   * Returns registration options (challenge) for key registration.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response with registration options or error.
   */
  public function registerOptions(Request $request): JsonResponse {
    try {
      $uid = (int) $this->currentUser()->id();
      $account = $this->entityTypeManager()->getStorage('user')->load($uid);
      $description = $request->query->get('description', 'Security Key');

      $result = $this->webauthnManager->beginRegistration($uid, $account->getAccountName(), $description);

      $session = $request->getSession();
      $session->set('webauthn_challenge', $result['challenge']);
      $session->set('webauthn_reg_description', $result['description']);

      return new JsonResponse([
        'success' => TRUE,
        'options' => $result['args'],
      ]);
    }
    catch (\Exception $e) {
      return new JsonResponse([
        'success' => FALSE,
        'error' => $e->getMessage(),
      ], 400);
    }
  }

  /**
   * Completes a key registration ceremony.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response with registration result.
   */
  public function registerVerify(Request $request): JsonResponse {
    try {
      $uid = (int) $this->currentUser()->id();
      $session = $request->getSession();
      $challenge = $session->get('webauthn_challenge');
      $description = $session->get('webauthn_reg_description', 'Security Key');

      if (!$challenge) {
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'No challenge found in session.',
        ], 400);
      }

      $content = json_decode($request->getContent(), TRUE);
      if (!$content) {
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Invalid request body.',
        ], 400);
      }

      $this->webauthnManager->finishRegistration(
        $uid,
        $challenge,
        $content['clientDataJSON'] ?? '',
        $content['attestationObject'] ?? '',
        $description,
        $content['transports'] ?? ''
      );

      // Clear session data.
      $session->remove('webauthn_challenge');
      $session->remove('webauthn_reg_description');

      return new JsonResponse(['success' => TRUE]);
    }
    catch (\Exception $e) {
      return new JsonResponse([
        'success' => FALSE,
        'error' => $e->getMessage(),
      ], 400);
    }
  }

  /**
   * Deletes a credential.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response with deletion result.
   */
  public function deleteCredential(Request $request): JsonResponse {
    $uid = (int) $this->currentUser()->id();
    $content = json_decode($request->getContent(), TRUE);
    $db_id = (int) ($content['id'] ?? 0);

    if (!$db_id) {
      return new JsonResponse([
        'success' => FALSE,
        'error' => 'Missing credential ID.',
      ], 400);
    }

    // Under 'required' policy, don't allow deleting the last 2FA method.
    $config = $this->config('webauthn.settings');
    if ($config->get('policy') === 'required') {
      $count = $this->webauthnManager->countCredentials($uid);
      $has_totp = $this->totpManager->userHasTotp($uid);
      if ($count <= 1 && !$has_totp) {
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Cannot delete your last security key while 2FA is required and no authenticator app is configured.',
        ], 400);
      }
    }

    $deleted = $this->webauthnManager->deleteCredential($uid, $db_id);

    return new JsonResponse(['success' => $deleted]);
  }

  /**
   * Toggles 2FA enabled/disabled for the current user.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response with toggle result.
   */
  public function toggle2fa(Request $request): JsonResponse {
    $uid = (int) $this->currentUser()->id();
    $content = json_decode($request->getContent(), TRUE);
    $enabled = !empty($content['enabled']);

    // Must have at least one 2FA method to enable.
    if ($enabled) {
      $has_keys = $this->webauthnManager->userHasCredentials($uid);
      $has_totp = $this->totpManager->userHasTotp($uid);
      if (!$has_keys && !$has_totp) {
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Set up at least one 2FA method (security key or authenticator app) before enabling.',
        ], 400);
      }
    }

    $this->userData->set('webauthn', $uid, '2fa_enabled', $enabled ? 1 : 0);

    return new JsonResponse(['success' => TRUE]);
  }

  /**
   * Begins TOTP setup: generates secret, returns QR code SVG.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response with secret and QR code SVG.
   */
  public function totpSetup(Request $request): JsonResponse {
    try {
      $uid = (int) $this->currentUser()->id();
      $account = $this->entityTypeManager()->getStorage('user')->load($uid);

      $secret = $this->totpManager->generateSecret();
      $uri = $this->totpManager->getProvisioningUri($secret, $account->getAccountName());
      $qr_svg = $this->totpManager->renderQrCode($uri);

      // Store secret in session until confirmed.
      $session = $request->getSession();
      $session->set('webauthn_totp_pending_secret', $secret);

      return new JsonResponse([
        'success' => TRUE,
        'secret' => $secret,
        'qrSvg' => $qr_svg,
      ]);
    }
    catch (\Exception $e) {
      return new JsonResponse([
        'success' => FALSE,
        'error' => $e->getMessage(),
      ], 400);
    }
  }

  /**
   * Confirms TOTP setup by verifying a code against the pending secret.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response with confirmation result.
   */
  public function totpConfirm(Request $request): JsonResponse {
    $uid = (int) $this->currentUser()->id();
    $session = $request->getSession();
    $secret = $session->get('webauthn_totp_pending_secret');

    if (!$secret) {
      return new JsonResponse([
        'success' => FALSE,
        'error' => 'No TOTP setup in progress.',
      ], 400);
    }

    $content = json_decode($request->getContent(), TRUE);
    $code = trim($content['code'] ?? '');

    if (!$code) {
      return new JsonResponse([
        'success' => FALSE,
        'error' => 'Please enter the 6-digit code.',
      ], 400);
    }

    if (!$this->totpManager->verifyCode($secret, $code)) {
      return new JsonResponse([
        'success' => FALSE,
        'error' => 'Invalid code. Please check the time on your device and try again.',
      ], 400);
    }

    // Save the confirmed secret.
    $this->totpManager->saveSecret($uid, $secret);
    $session->remove('webauthn_totp_pending_secret');

    return new JsonResponse(['success' => TRUE]);
  }

  /**
   * Removes TOTP configuration for the current user.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response with removal result.
   */
  public function totpRemove(Request $request): JsonResponse {
    $uid = (int) $this->currentUser()->id();

    // Under 'required' policy, don't allow removing TOTP if it's the last method.
    $config = $this->config('webauthn.settings');
    if ($config->get('policy') === 'required') {
      $has_keys = $this->webauthnManager->userHasCredentials($uid);
      if (!$has_keys) {
        return new JsonResponse([
          'success' => FALSE,
          'error' => 'Cannot remove authenticator app while 2FA is required and no security keys are registered.',
        ], 400);
      }
    }

    $this->totpManager->removeSecret($uid);

    return new JsonResponse(['success' => TRUE]);
  }

  /**
   * Verifies a TOTP code during 2FA gate.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response with verification result.
   */
  public function totpVerify(Request $request): JsonResponse {
    $uid = (int) $this->currentUser()->id();
    $session = $request->getSession();

    $secret = $this->totpManager->getSecret($uid);
    if (!$secret) {
      return new JsonResponse([
        'success' => FALSE,
        'error' => 'No authenticator app configured.',
      ], 400);
    }

    $content = json_decode($request->getContent(), TRUE);
    $code = trim($content['code'] ?? '');

    if (!$code) {
      return new JsonResponse([
        'success' => FALSE,
        'error' => 'Please enter the 6-digit code.',
      ], 400);
    }

    if (!$this->totpManager->verifyCode($secret, $code)) {
      return new JsonResponse([
        'success' => FALSE,
        'error' => 'Invalid code. Please try again.',
      ], 400);
    }

    return $this->complete2fa($session, $uid, 'totp');
  }

  /**
   * Completes one step of 2FA/MFA verification.
   *
   * In "any" mode, a single method clears the gate.
   * In "all" mode, every configured method must be verified before the gate
   * clears — making this true MFA when both WebAuthn and TOTP are set up.
   *
   * @param \Symfony\Component\HttpFoundation\Session\SessionInterface $session
   *   The Symfony session.
   * @param int $uid
   *   Drupal user ID.
   * @param string $method
   *   The method just verified: 'webauthn' or 'totp'.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response indicating completion or partial progress.
   */
  protected function complete2fa(SessionInterface $session, int $uid, string $method): JsonResponse {
    $config = $this->config('webauthn.settings');
    $mode = $config->get('verification_mode') ?: 'any';

    if ($mode === 'all') {
      // Track which methods have been completed this session.
      $completed = $session->get('webauthn_mfa_completed', []);
      if (!in_array($method, $completed, TRUE)) {
        $completed[] = $method;
      }
      $session->set('webauthn_mfa_completed', $completed);

      // Determine which methods this user has configured.
      $required = [];
      if ($this->webauthnManager->userHasCredentials($uid)) {
        $required[] = 'webauthn';
      }
      if ($this->totpManager->userHasTotp($uid)) {
        $required[] = 'totp';
      }

      $remaining = array_values(array_diff($required, $completed));

      if (!empty($remaining)) {
        // More factors needed — return partial success.
        return new JsonResponse([
          'success' => TRUE,
          'partial' => TRUE,
          'completed' => $method,
          'remaining' => $remaining,
        ]);
      }

      // All methods verified — clean up and redirect.
      $session->remove('webauthn_mfa_completed');
    }

    // Clear the gate.
    $session->remove('webauthn_2fa_pending');

    $destination = $session->get('webauthn_2fa_destination');
    $session->remove('webauthn_2fa_destination');

    $redirect = $destination ?: Url::fromRoute('entity.user.canonical', ['user' => $uid])->toString();

    return new JsonResponse([
      'success' => TRUE,
      'redirect' => $redirect,
    ]);
  }

}
