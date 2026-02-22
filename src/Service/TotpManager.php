<?php

namespace Drupal\webauthn\Service;

use chillerlan\QRCode\QRCode;
use chillerlan\QRCode\QROptions;
use Drupal\Core\Config\ConfigFactoryInterface;
use ParagonIE\ConstantTime\Base32;
use OTPHP\TOTP;

/**
 * TOTP (Time-based One-Time Password) management service.
 *
 * Handles secret generation, QR code rendering, and code verification
 * for authenticator app 2FA (Google Authenticator, andOTP, FreeOTP, etc.).
 */
class TotpManager {

  /**
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $config;

  /**
   * Constructs a TotpManager.
   */
  public function __construct(ConfigFactoryInterface $config_factory) {
    $this->config = $config_factory->get('webauthn.settings');
  }

  /**
   * Generate a new random TOTP secret.
   *
   * @return string
   *   Base32-encoded secret.
   */
  public function generateSecret() {
    // Use 20 bytes (160 bits, standard for SHA1 TOTP) instead of the
    // library's default 64 bytes, which produces QR codes too dense
    // for many phone cameras to scan reliably.
    return Base32::encodeUpper(random_bytes(20));
  }

  /**
   * Get the otpauth:// provisioning URI for a secret.
   *
   * @param string $secret
   *   Base32-encoded TOTP secret.
   * @param string $username
   *   Account name / email shown in the authenticator app.
   *
   * @return string
   *   otpauth://totp/... URI.
   */
  public function getProvisioningUri($secret, $username) {
    $totp = TOTP::create($secret);
    $totp->setLabel($username);

    $issuer = $this->config->get('rp_name')
      ?: \Drupal::config('system.site')->get('name')
      ?: 'Drupal';
    $totp->setIssuer($issuer);

    return $totp->getProvisioningUri();
  }

  /**
   * Render a QR code as inline SVG markup.
   *
   * @param string $uri
   *   The otpauth:// URI to encode.
   *
   * @return string
   *   Raw SVG markup string.
   */
  public function renderQrCode($uri) {
    $options = new QROptions([
      'outputType' => QRCode::OUTPUT_MARKUP_SVG,
      'imageBase64' => FALSE,
      'eccLevel' => QRCode::ECC_L,
      'addQuietzone' => TRUE,
    ]);

    return (new QRCode($options))->render($uri);
  }

  /**
   * Verify a 6-digit TOTP code against a secret.
   *
   * @param string $secret
   *   Base32-encoded TOTP secret.
   * @param string $code
   *   The 6-digit code entered by the user.
   *
   * @return bool
   *   TRUE if the code is valid.
   */
  public function verifyCode($secret, $code) {
    $totp = TOTP::create($secret);
    // Window of 10 allows +/- 5 minutes clock drift.
    return $totp->verify($code, NULL, 10);
  }

  /**
   * Save a confirmed TOTP secret for a user.
   *
   * @param int $uid
   *   Drupal user ID.
   * @param string $secret
   *   Base32-encoded TOTP secret.
   */
  public function saveSecret($uid, $secret) {
    \Drupal::service('user.data')->set('webauthn', $uid, 'totp_secret', $secret);
  }

  /**
   * Get the stored TOTP secret for a user.
   *
   * @param int $uid
   *   Drupal user ID.
   *
   * @return string|null
   *   The secret, or NULL if not configured.
   */
  public function getSecret($uid) {
    return \Drupal::service('user.data')->get('webauthn', $uid, 'totp_secret');
  }

  /**
   * Remove the TOTP secret for a user.
   *
   * @param int $uid
   *   Drupal user ID.
   */
  public function removeSecret($uid) {
    \Drupal::service('user.data')->delete('webauthn', $uid, 'totp_secret');
  }

  /**
   * Check whether a user has TOTP configured.
   *
   * @param int $uid
   *   Drupal user ID.
   *
   * @return bool
   */
  public function userHasTotp($uid) {
    return !empty($this->getSecret($uid));
  }

}
