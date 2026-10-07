<?php

declare(strict_types=1);

namespace Drupal\webauthn\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Datetime\DateFormatterInterface;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Core\Url;
use Drupal\user\UserDataInterface;
use Drupal\webauthn\DestinationHelper;
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
   * Flood event name for TOTP verification attempts.
   */
  const TOTP_FLOOD_EVENT = 'webauthn.totp_verify';

  /**
   * Maximum TOTP verification attempts per user in the short window.
   */
  const TOTP_FLOOD_SHORT_LIMIT = 5;

  /**
   * Short flood window in seconds.
   */
  const TOTP_FLOOD_SHORT_WINDOW = 900;

  /**
   * Maximum TOTP verification attempts per user in the long window.
   */
  const TOTP_FLOOD_LONG_LIMIT = 20;

  /**
   * Long flood window in seconds.
   */
  const TOTP_FLOOD_LONG_WINDOW = 86400;

  /**
   * The flood service.
   *
   * @var \Drupal\Core\Flood\FloodInterface
   */
  protected FloodInterface $flood;

  /**
   * The date formatter.
   *
   * @var \Drupal\Core\Datetime\DateFormatterInterface
   */
  protected DateFormatterInterface $dateFormatter;

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
    $instance->flood = $container->get('flood');
    $instance->dateFormatter = $container->get('date.formatter');
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

    $code = $this->getSubmittedCode($request);

    if ($code === NULL) {
      return new JsonResponse([
        'success' => FALSE,
        'error' => 'Please enter the 6-digit code.',
      ], 400);
    }

    // Consuming the code here also stops it being replayed at the next login.
    if (!$this->totpManager->verifyAndConsume($uid, $secret, $code)) {
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

    $code = $this->getSubmittedCode($request);

    if ($code === NULL) {
      return new JsonResponse([
        'success' => FALSE,
        'error' => 'Please enter the 6-digit code.',
      ], 400);
    }

    $flood_id = 'uid:' . $uid;
    // Refuse while locked without recording anything, so refused requests
    // do not extend the lock.
    if ($retry_after = $this->getTotpLockout($flood_id, 0)) {
      return $this->totpLockedResponse($uid, $retry_after);
    }
    // Record the attempt before checking the code, so concurrent requests
    // cannot all pass the limit before any failure is stored. The count then
    // includes this attempt.
    $this->flood->register(self::TOTP_FLOOD_EVENT, self::TOTP_FLOOD_LONG_WINDOW, $flood_id);
    if ($retry_after = $this->getTotpLockout($flood_id, 1)) {
      return $this->totpLockedResponse($uid, $retry_after);
    }

    if (!$this->totpManager->verifyAndConsume($uid, $secret, $code)) {
      $this->getLogger('webauthn')->notice('Invalid authenticator code for user @uid.', ['@uid' => $uid]);
      // Log the lockout once, as it is reached; later refusals stay silent so
      // they cannot be used to flood the log.
      if ($this->getTotpLockout($flood_id, 0)) {
        $this->getLogger('webauthn')->warning('Authenticator code verification locked for user @uid after too many attempts.', ['@uid' => $uid]);
      }
      return new JsonResponse([
        'success' => FALSE,
        'error' => 'Invalid code. Please try again.',
      ], 400);
    }

    $this->flood->clear(self::TOTP_FLOOD_EVENT, $flood_id);
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

    // Clear the gate, give the now fully authenticated session a new ID, and
    // record that it completed 2FA.
    $session->remove('webauthn_2fa_pending');
    $session->migrate();
    $session->set('webauthn_2fa_ok', $uid);
    $this->getLogger('webauthn')->info('Two-factor verification completed for user @uid (@method).', [
      '@uid' => $uid,
      '@method' => $method,
    ]);

    // Previous login details are only shown once the second factor passed.
    $prev_time = (int) $session->get('webauthn_prev_login_time', 0);
    $prev_ip = (string) $session->get('webauthn_prev_login_ip', '');
    $session->remove('webauthn_prev_login_time');
    $session->remove('webauthn_prev_login_ip');
    if ($prev_time) {
      $time = $this->dateFormatter->format($prev_time, 'medium');
      $this->messenger()->addStatus($prev_ip !== ''
        ? $this->t('Last login: @time from @ip', ['@time' => $time, '@ip' => $prev_ip])
        : $this->t('Last login: @time', ['@time' => $time]));
    }

    $destination = DestinationHelper::localPath($session->get('webauthn_2fa_destination'));
    $session->remove('webauthn_2fa_destination');

    $redirect = $destination ?: Url::fromRoute('entity.user.canonical', ['user' => $uid])->toString();

    return new JsonResponse([
      'success' => TRUE,
      'redirect' => $redirect,
    ]);
  }

  /**
   * Gets the submitted 6-digit code from a JSON request body.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return string|null
   *   The code, or NULL if the body does not contain exactly six digits.
   */
  protected function getSubmittedCode(Request $request): ?string {
    $content = json_decode($request->getContent(), TRUE);
    $code = is_array($content) ? ($content['code'] ?? NULL) : NULL;
    if (!is_string($code)) {
      return NULL;
    }
    $code = preg_replace('/\s+/', '', $code);
    return preg_match('/^\d{6}$/', $code) ? $code : NULL;
  }

  /**
   * Checks whether TOTP verification is locked for a flood identifier.
   *
   * @param string $flood_id
   *   The flood identifier.
   * @param int $included
   *   Number of attempts already recorded for the current request (0 or 1).
   *
   * @return int
   *   Seconds until the lock may expire (an upper bound), or 0 if unlocked.
   */
  protected function getTotpLockout(string $flood_id, int $included): int {
    if (!$this->flood->isAllowed(self::TOTP_FLOOD_EVENT, self::TOTP_FLOOD_LONG_LIMIT + $included, self::TOTP_FLOOD_LONG_WINDOW, $flood_id)) {
      return self::TOTP_FLOOD_LONG_WINDOW;
    }
    if (!$this->flood->isAllowed(self::TOTP_FLOOD_EVENT, self::TOTP_FLOOD_SHORT_LIMIT + $included, self::TOTP_FLOOD_SHORT_WINDOW, $flood_id)) {
      return self::TOTP_FLOOD_SHORT_WINDOW;
    }
    return 0;
  }

  /**
   * Builds the response for a locked TOTP verification.
   *
   * @param int $uid
   *   The user ID.
   * @param int $retry_after
   *   Seconds until the lock may expire.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   A 429 response.
   */
  protected function totpLockedResponse(int $uid, int $retry_after): JsonResponse {
    return new JsonResponse([
      'success' => FALSE,
      'error' => 'Too many attempts. Please try again later.',
    ], 429, ['Retry-After' => (string) $retry_after]);
  }

}
