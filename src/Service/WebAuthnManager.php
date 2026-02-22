<?php

namespace Drupal\webauthn\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use lbuchs\WebAuthn\WebAuthn;
use lbuchs\WebAuthn\Binary\ByteBuffer;

/**
 * WebAuthn ceremony logic and credential storage.
 *
 * Ported from Roundcube WebAuthn plugin's WebAuthnManager.
 */
class WebAuthnManager {

  /**
   * @var \Drupal\Core\Database\Connection
   */
  protected $database;

  /**
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $config;

  /**
   * @var \lbuchs\WebAuthn\WebAuthn
   */
  protected $webauthn;

  /**
   * Constructs a WebAuthnManager.
   */
  public function __construct(Connection $database, ConfigFactoryInterface $config_factory) {
    $this->database = $database;
    $this->config = $config_factory->get('webauthn.settings');

    $rp_name = $this->config->get('rp_name') ?: \Drupal::config('system.site')->get('name') ?: 'Drupal';
    $rp_id = $this->config->get('rp_id') ?: (\Drupal::request()->getHost() ?: 'localhost');
    // Strip port from rp_id if present.
    if (strpos($rp_id, ':') !== FALSE) {
      $rp_id = explode(':', $rp_id, 2)[0];
    }

    $formats = ['android-key', 'android-safetynet', 'apple', 'fido-u2f', 'none', 'packed', 'tpm'];
    $this->webauthn = new WebAuthn($rp_name, $rp_id, $formats, TRUE);
  }

  /**
   * Check whether a user has any registered credentials.
   */
  public function userHasCredentials($uid) {
    return $this->countCredentials($uid) > 0;
  }

  /**
   * Count registered credentials for a user.
   */
  public function countCredentials($uid) {
    return (int) $this->database->select('webauthn_credentials', 'wc')
      ->condition('uid', $uid)
      ->countQuery()
      ->execute()
      ->fetchField();
  }

  /**
   * Get all credentials for a user.
   */
  public function getCredentials($uid) {
    return $this->database->select('webauthn_credentials', 'wc')
      ->fields('wc')
      ->condition('uid', $uid)
      ->orderBy('created', 'DESC')
      ->execute()
      ->fetchAll();
  }

  /**
   * Get a single credential by its DB id and user.
   */
  public function getCredentialByDbId($uid, $db_id) {
    return $this->database->select('webauthn_credentials', 'wc')
      ->fields('wc')
      ->condition('id', $db_id)
      ->condition('uid', $uid)
      ->execute()
      ->fetchObject();
  }

  /**
   * Check whether 2FA should be enforced for a user based on policy.
   */
  public function should2fa($uid) {
    $policy = $this->config->get('policy') ?: 'optional';

    if ($policy === 'disabled') {
      return FALSE;
    }

    $has_credentials = $this->userHasCredentials($uid);
    /** @var \Drupal\webauthn\Service\TotpManager $totp_manager */
    $totp_manager = \Drupal::service('webauthn.totp_manager');
    $has_totp = $totp_manager->userHasTotp($uid);
    $has_any_method = $has_credentials || $has_totp;

    if ($policy === 'required') {
      // Required: enforce if user has any 2FA method configured.
      return $has_any_method;
    }

    // Optional: check user preference.
    if (!$has_any_method) {
      return FALSE;
    }

    $user_data = \Drupal::service('user.data');
    $enabled = $user_data->get('webauthn', $uid, '2fa_enabled');
    return !empty($enabled);
  }

  /**
   * Begin a registration ceremony.
   *
   * @return array
   *   ['args' => PublicKeyCredentialCreationOptions, 'challenge' => binary]
   */
  public function beginRegistration($uid, $username, $description) {
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
   * Complete a registration ceremony.
   */
  public function finishRegistration($uid, $challenge, $client_data, $attestation_obj, $description, $transports = '') {
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

    $now = \Drupal::time()->getRequestTime();

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
   * Begin an assertion (authentication) ceremony.
   *
   * @return array
   *   ['args' => PublicKeyCredentialRequestOptions, 'challenge' => binary]
   */
  public function beginAssertion($uid) {
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
      TRUE,   // allowUsb
      TRUE,   // allowNfc
      TRUE,   // allowBle
      FALSE,  // allowHybrid
      TRUE,   // allowInternal
      $uv
    );

    $challenge = $this->webauthn->getChallenge()->getBinaryString();

    return [
      'args' => $args,
      'challenge' => $challenge,
    ];
  }

  /**
   * Complete an assertion (authentication) ceremony.
   */
  public function finishAssertion($uid, $challenge, $credential_id, $client_data, $authenticator_data, $signature) {
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
    $now = \Drupal::time()->getRequestTime();

    if ($new_count !== NULL) {
      // Clone detection: counter must strictly increase (unless both are 0).
      $old_count = (int) $credential->sign_count;
      $clone_warning = 0;
      if ($old_count > 0 && $new_count <= $old_count) {
        $clone_warning = 1;
        \Drupal::logger('webauthn')->warning('Clone warning: credential @cred_id for user @uid — counter went from @old to @new', [
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
   * Delete a credential by its DB id.
   */
  public function deleteCredential($uid, $db_id) {
    return $this->database->delete('webauthn_credentials')
      ->condition('id', $db_id)
      ->condition('uid', $uid)
      ->execute() > 0;
  }

  /**
   * Find a credential by raw binary credential ID.
   */
  protected function findCredentialByRawId($uid, $cred_id_bin) {
    $credentials = $this->getCredentials($uid);
    foreach ($credentials as $cred) {
      if ($cred->credential_id === $cred_id_bin) {
        return $cred;
      }
    }
    return NULL;
  }

}
