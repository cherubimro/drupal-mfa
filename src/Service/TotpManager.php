<?php

declare(strict_types=1);

namespace Drupal\webauthn\Service;

use chillerlan\QRCode\QRCode;
use chillerlan\QRCode\QROptions;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\user\UserDataInterface;
use OTPHP\TOTP;
use ParagonIE\ConstantTime\Base32;

/**
 * TOTP (Time-based One-Time Password) management service.
 *
 * Handles secret generation, QR code rendering, and code verification
 * for authenticator app 2FA (Google Authenticator, andOTP, FreeOTP, etc.).
 */
class TotpManager {

  /**
   * The module configuration.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected ImmutableConfig $config;

  /**
   * The user data service.
   *
   * @var \Drupal\user\UserDataInterface
   */
  protected UserDataInterface $userData;

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected ConfigFactoryInterface $configFactory;

  /**
   * Constructs a TotpManager.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\user\UserDataInterface $user_data
   *   The user data service.
   */
  public function __construct(ConfigFactoryInterface $config_factory, UserDataInterface $user_data) {
    $this->configFactory = $config_factory;
    $this->config = $config_factory->get('webauthn.settings');
    $this->userData = $user_data;
  }

  /**
   * Generates a new random TOTP secret.
   *
   * @return string
   *   Base32-encoded secret.
   */
  public function generateSecret(): string {
    // Use 20 bytes (160 bits, standard for SHA1 TOTP) instead of the
    // library's default 64 bytes, which produces QR codes too dense
    // for many phone cameras to scan reliably.
    return Base32::encodeUpper(random_bytes(20));
  }

  /**
   * Gets the otpauth:// provisioning URI for a secret.
   *
   * @param string $secret
   *   Base32-encoded TOTP secret.
   * @param string $username
   *   Account name / email shown in the authenticator app.
   *
   * @return string
   *   otpauth://totp/... URI.
   */
  public function getProvisioningUri(string $secret, string $username): string {
    $totp = TOTP::create($secret);
    $totp->setLabel($username);

    $issuer = $this->config->get('rp_name')
      ?: $this->configFactory->get('system.site')->get('name')
      ?: 'Drupal';
    $totp->setIssuer($issuer);

    return $totp->getProvisioningUri();
  }

  /**
   * Renders a QR code as inline SVG markup.
   *
   * @param string $uri
   *   The otpauth:// URI to encode.
   *
   * @return string
   *   Raw SVG markup string.
   */
  public function renderQrCode(string $uri): string {
    $options = new QROptions([
      'outputType' => QRCode::OUTPUT_MARKUP_SVG,
      'imageBase64' => FALSE,
      'eccLevel' => QRCode::ECC_L,
      'addQuietzone' => TRUE,
    ]);

    return (new QRCode($options))->render($uri);
  }

  /**
   * Verifies a 6-digit TOTP code against a secret.
   *
   * @param string $secret
   *   Base32-encoded TOTP secret.
   * @param string $code
   *   The 6-digit code entered by the user.
   *
   * @return bool
   *   TRUE if the code is valid.
   */
  public function verifyCode(string $secret, string $code): bool {
    $totp = TOTP::create($secret);
    // Window of 10 allows +/- 5 minutes clock drift.
    return $totp->verify($code, NULL, 10);
  }

  /**
   * Saves a confirmed TOTP secret for a user.
   *
   * @param int $uid
   *   Drupal user ID.
   * @param string $secret
   *   Base32-encoded TOTP secret.
   */
  public function saveSecret(int $uid, string $secret): void {
    $this->userData->set('webauthn', $uid, 'totp_secret', $secret);
  }

  /**
   * Gets the stored TOTP secret for a user.
   *
   * @param int $uid
   *   Drupal user ID.
   *
   * @return string|null
   *   The secret, or NULL if not configured.
   */
  public function getSecret(int $uid): ?string {
    return $this->userData->get('webauthn', $uid, 'totp_secret');
  }

  /**
   * Removes the TOTP secret for a user.
   *
   * @param int $uid
   *   Drupal user ID.
   */
  public function removeSecret(int $uid): void {
    $this->userData->delete('webauthn', $uid, 'totp_secret');
  }

  /**
   * Checks whether a user has TOTP configured.
   *
   * @param int $uid
   *   Drupal user ID.
   *
   * @return bool
   *   TRUE if the user has a TOTP secret stored.
   */
  public function userHasTotp(int $uid): bool {
    return !empty($this->getSecret($uid));
  }

}
