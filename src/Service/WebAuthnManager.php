<?php

declare(strict_types=1);

namespace Drupal\webauthn\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\Database\Connection;
use Drupal\Component\Datetime\TimeInterface;
use Drupal\user\UserDataInterface;
use lbuchs\WebAuthn\Binary\ByteBuffer;
use lbuchs\WebAuthn\WebAuthn;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * WebAuthn ceremony logic and credential storage.
 *
 * Ported from Roundcube WebAuthn plugin's WebAuthnManager.
 */
class WebAuthnManager {

  /**
   * The database connection.
   *
   * @var \Drupal\Core\Database\Connection
   */
  protected Connection $database;

  /**
   * The module configuration.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected ImmutableConfig $config;

  /**
   * The WebAuthn library instance.
   *
   * @var \lbuchs\WebAuthn\WebAuthn
   */
  protected WebAuthn $webauthn;

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
   * The time service.
   *
   * @var \Drupal\Component\Datetime\TimeInterface
   */
  protected TimeInterface $time;

  /**
   * The logger.
   *
   * @var \Psr\Log\LoggerInterface
   */
  protected LoggerInterface $logger;

  /**
   * Constructs a WebAuthnManager.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\webauthn\Service\TotpManager $totp_manager
   *   The TOTP manager service.
   * @param \Drupal\user\UserDataInterface $user_data
   *   The user data service.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   * @param \Psr\Log\LoggerInterface $logger
   *   The logger.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request_stack
   *   The request stack.
   */
  public function __construct(
    Connection $database,
    ConfigFactoryInterface $config_factory,
    TotpManager $totp_manager,
    UserDataInterface $user_data,
    TimeInterface $time,
    LoggerInterface $logger,
    RequestStack $request_stack,
  ) {
    $this->database = $database;
    $this->config = $config_factory->get('webauthn.settings');
    $this->totpManager = $totp_manager;
    $this->userData = $user_data;
    $this->time = $time;
    $this->logger = $logger;

    $rp_name = $this->config->get('rp_name')
      ?: $config_factory->get('system.site')->get('name')
      ?: 'Drupal';
    $host = $request_stack->getCurrentRequest()?->getHost() ?? 'localhost';
    $rp_id = $this->config->get('rp_id') ?: $host;
    // Strip port from rp_id if present.
    if (strpos($rp_id, ':') !== FALSE) {
      $rp_id = explode(':', $rp_id, 2)[0];
    }

    $formats = ['android-key', 'android-safetynet', 'apple', 'fido-u2f', 'none', 'packed', 'tpm'];
    $this->webauthn = new WebAuthn($rp_name, $rp_id, $formats, TRUE);
  }

  /**
   * Checks whether a user has any registered credentials.
   *
   * @param int $uid
   *   The Drupal user ID.
   *
   * @return bool
   *   TRUE if the user has at least one credential.
   */
  public function userHasCredentials(int $uid): bool {
    return $this->countCredentials($uid) > 0;
  }

  /**
   * Counts registered credentials for a user.
   *
   * @param int $uid
   *   The Drupal user ID.
   *
   * @return int
   *   The number of credentials.
   */
  public function countCredentials(int $uid): int {
    return (int) $this->database->select('webauthn_credentials', 'wc')
      ->condition('uid', $uid)
      ->countQuery()
      ->execute()
      ->fetchField();
  }

  /**
   * Gets all credentials for a user.
   *
   * @param int $uid
   *   The Drupal user ID.
   *
   * @return array
   *   Array of credential objects.
   */
  public function getCredentials(int $uid): array {
    return $this->database->select('webauthn_credentials', 'wc')
      ->fields('wc')
      ->condition('uid', $uid)
      ->orderBy('created', 'DESC')
      ->execute()
      ->fetchAll();
  }

  /**
   * Gets a single credential by its DB id and user.
   *
   * @param int $uid
   *   The Drupal user ID.
   * @param int $db_id
   *   The database row ID.
   *
   * @return object|null
   *   The credential object, or NULL if not found.
   */
  public function getCredentialByDbId(int $uid, int $db_id): ?object {
    return $this->database->select('webauthn_credentials', 'wc')
      ->fields('wc')
      ->condition('id', $db_id)
      ->condition('uid', $uid)
      ->execute()
      ->fetchObject() ?: NULL;
  }

  /**
   * Checks whether 2FA should be enforced for a user based on policy.
   *
   * @param int $uid
   *   The Drupal user ID.
   *
   * @return bool
   *   TRUE if 2FA should be enforced.
   */
  public function should2fa(int $uid): bool {
    $policy = $this->config->get('policy') ?: 'optional';

    if ($policy === 'disabled') {
      return FALSE;
    }

    $has_credentials = $this->userHasCredentials($uid);
    $has_totp = $this->totpManager->userHasTotp($uid);
    $has_any_method = $has_credentials || $has_totp;

    if ($policy === 'required') {
      // Required: enforce if user has any 2FA method configured.
      return $has_any_method;
    }

    // Optional: check user preference.
    if (!$has_any_method) {
      return FALSE;
    }

    $enabled = $this->userData->get('webauthn', $uid, '2fa_enabled');
    return !empty($enabled);
  }

  /**
   * Begins a registration ceremony.
   *
   * @param int $uid
   *   The Drupal user ID.
   * @param string $username
   *   The account name.
   * @param string $description
   *   A user-given key name.
   *
   * @return array
   *   Array with 'args', 'challenge', and 'description' keys.
   */
  public function beginRegistration(int $uid, string $username, string $description): array {
    $timeout = (int) ($this->config->get('timeout') ?: 60000);
    $uv = ($this->config->get('user_verification') ?: 'preferred') === 'required';
    $attestation = $this->config->get('attestation') ?: 'none';
    $attachment = $this->config->get('attachment') ?: '';

    // Map attachment config to library parameter.
    $cross_platform = NULL;
    if ($attachment === 'cross-platform') {
      $cross_platform = TRUE;
    }
    elseif ($attachment === 'platform') {
      $cross_platform = FALSE;
    }

    // Get existing credential IDs to exclude (prevent re-registration).
    $existing = $this->getCredentials($uid);
    $exclude = [];
    foreach ($existing as $cred) {
      $exclude[] = new ByteBuffer($cred->credential_id);
    }

    // User handle: hash of uid for privacy.
    $user_handle = hash('sha256', 'webauthn_user_' . $uid, TRUE);

    $args = $this->webauthn->getCreateArgs(
      $user_handle,
      $username,
      $username,
      $timeout / 1000,
      FALSE,
      $uv,
      $cross_platform,
      $exclude
    );

    // Override attestation preference.
    if (isset($args->publicKey->attestation)) {
      $args->publicKey->attestation = $attestation;
    }

    $challenge = $this->webauthn->getChallenge()->getBinaryString();

    return [
      'args' => $args,
      'challenge' => $challenge,
      'description' => $description,
    ];
  }

  /**
   * Completes a registration ceremony.
   *
   * @param int $uid
   *   The Drupal user ID.
   * @param string $challenge
   *   The binary challenge string from the session.
   * @param string $client_data
   *   Base64url-encoded client data JSON.
   * @param string $attestation_obj
   *   Base64url-encoded attestation object.
   * @param string $description
   *   A user-given key name.
   * @param string $transports
   *   Comma-separated transport hints.
   *
   * @return bool
   *   TRUE on success.
   */
  public function finishRegistration(int $uid, string $challenge, string $client_data, string $attestation_obj, string $description, string $transports = ''): bool {
    $uv = ($this->config->get('user_verification') ?: 'preferred') === 'required';
    $challenge_buf = new ByteBuffer($challenge);

    $data = $this->webauthn->processCreate(
      base64_decode(strtr($client_data, '-_', '+/')),
      base64_decode(strtr($attestation_obj, '-_', '+/')),
      $challenge_buf,
      $uv,
      TRUE,
      FALSE
    );

    // credentialId: ByteBuffer or raw binary string from the library.
    if ($data->credentialId instanceof ByteBuffer) {
      $credential_id = $data->credentialId->getBinaryString();
    }
    else {
      $credential_id = $data->credentialId;
    }

    $now = $this->time->getRequestTime();

    $this->database->insert('webauthn_credentials')
      ->fields([
        'uid' => $uid,
        'description' => $description,
        'credential_id' => $credential_id,
        'public_key' => $data->credentialPublicKey,
        'aaguid' => $data->AAGUID ?? '',
        'attestation_type' => $data->attestationFormat ?? 'none',
        'attachment' => '',
        'transports' => $transports,
        'sign_count' => (int) ($data->signatureCounter ?? 0),
        'clone_warning' => 0,
        'user_verified' => $data->userVerified ? 1 : 0,
        'backup_eligible' => $data->isBackupEligible ? 1 : 0,
        'created' => $now,
        'last_used' => NULL,
      ])
      ->execute();

    return TRUE;
  }

  /**
   * Begins an assertion (authentication) ceremony.
   *
   * @param int $uid
   *   The Drupal user ID.
   *
   * @return array
   *   Array with 'args' and 'challenge' keys.
   *
   * @throws \RuntimeException
   *   If the user has no registered credentials.
   */
  public function beginAssertion(int $uid): array {
    $timeout = (int) ($this->config->get('timeout') ?: 60000);
    $uv = ($this->config->get('user_verification') ?: 'preferred') === 'required';

    $credentials = $this->getCredentials($uid);
    $cred_ids = [];
    foreach ($credentials as $cred) {
      $cred_ids[] = new ByteBuffer($cred->credential_id);
    }

    if (empty($cred_ids)) {
      throw new \RuntimeException('No credentials registered for this user');
    }

    $args = $this->webauthn->getGetArgs(
      $cred_ids,
      $timeout / 1000,
      TRUE,
      TRUE,
      TRUE,
      FALSE,
      TRUE,
      $uv
    );

    $challenge = $this->webauthn->getChallenge()->getBinaryString();

    return [
      'args' => $args,
      'challenge' => $challenge,
    ];
  }

  /**
   * Completes an assertion (authentication) ceremony.
   *
   * @param int $uid
   *   The Drupal user ID.
   * @param string $challenge
   *   The binary challenge string from the session.
   * @param string $credential_id
   *   Base64url-encoded credential ID.
   * @param string $client_data
   *   Base64url-encoded client data JSON.
   * @param string $authenticator_data
   *   Base64url-encoded authenticator data.
   * @param string $signature
   *   Base64url-encoded signature.
   *
   * @return bool
   *   TRUE on successful verification.
   *
   * @throws \RuntimeException
   *   If the credential is unknown or a clone is detected.
   */
  public function finishAssertion(int $uid, string $challenge, string $credential_id, string $client_data, string $authenticator_data, string $signature): bool {
    $cred_id_bin = base64_decode(strtr($credential_id, '-_', '+/'));
    $uv = ($this->config->get('user_verification') ?: 'preferred') === 'required';

    // Find the matching credential.
    $credential = $this->findCredentialByRawId($uid, $cred_id_bin);
    if (!$credential) {
      throw new \RuntimeException('Unknown credential');
    }

    $challenge_buf = new ByteBuffer($challenge);

    $result = $this->webauthn->processGet(
      base64_decode(strtr($client_data, '-_', '+/')),
      base64_decode(strtr($authenticator_data, '-_', '+/')),
      base64_decode(strtr($signature, '-_', '+/')),
      $credential->public_key,
      $challenge_buf,
      (int) $credential->sign_count,
      $uv,
      TRUE
    );

    if (!$result) {
      return FALSE;
    }

    // Update sign count and last used timestamp.
    $new_count = $this->webauthn->getSignatureCounter();
    $now = $this->time->getRequestTime();

    if ($new_count !== NULL) {
      // Clone detection: counter must strictly increase (unless both are 0).
      $old_count = (int) $credential->sign_count;
      $clone_warning = 0;
      if ($old_count > 0 && $new_count <= $old_count) {
        $clone_warning = 1;
        $this->logger->warning('Clone warning: credential @cred_id for user @uid — counter went from @old to @new', [
          '@cred_id' => $credential->id,
          '@uid' => $uid,
          '@old' => $old_count,
          '@new' => $new_count,
        ]);
      }

      $this->database->update('webauthn_credentials')
        ->fields([
          'sign_count' => $new_count,
          'clone_warning' => $clone_warning,
          'last_used' => $now,
        ])
        ->condition('id', $credential->id)
        ->execute();

      if ($clone_warning) {
        throw new \RuntimeException('Possible cloned authenticator detected');
      }
    }
    else {
      $this->database->update('webauthn_credentials')
        ->fields(['last_used' => $now])
        ->condition('id', $credential->id)
        ->execute();
    }

    return TRUE;
  }

  /**
   * Deletes a credential by its DB id.
   *
   * @param int $uid
   *   The Drupal user ID.
   * @param int $db_id
   *   The database row ID.
   *
   * @return bool
   *   TRUE if a row was deleted.
   */
  public function deleteCredential(int $uid, int $db_id): bool {
    return $this->database->delete('webauthn_credentials')
      ->condition('id', $db_id)
      ->condition('uid', $uid)
      ->execute() > 0;
  }

  /**
   * Finds a credential by raw binary credential ID.
   *
   * @param int $uid
   *   The Drupal user ID.
   * @param string $cred_id_bin
   *   The raw binary credential ID.
   *
   * @return object|null
   *   The credential object, or NULL if not found.
   */
  protected function findCredentialByRawId(int $uid, string $cred_id_bin): ?object {
    $credentials = $this->getCredentials($uid);
    foreach ($credentials as $cred) {
      if ($cred->credential_id === $cred_id_bin) {
        return $cred;
      }
    }
    return NULL;
  }

}
