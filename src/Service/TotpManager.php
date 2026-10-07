<?php

declare(strict_types=1);

namespace Drupal\webauthn\Service;

use chillerlan\QRCode\QRCode;
use chillerlan\QRCode\QROptions;
use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\Lock\LockBackendInterface;
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
   * Verification leeway in seconds; must stay below the 30s period.
   *
   * 15s allows for slow entry around a period boundary and accepts at most
   * two codes at any moment.
   */
  const LEEWAY = 15;

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
   * The clock used for OTP generation and verification.
   *
   * @var \Drupal\webauthn\Service\TotpClock
   */
  protected TotpClock $clock;

  /**
   * The lock backend.
   *
   * @var \Drupal\Core\Lock\LockBackendInterface
   */
  protected LockBackendInterface $lock;

  /**
   * Constructs a TotpManager.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\user\UserDataInterface $user_data
   *   The user data service.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   * @param \Drupal\Core\Lock\LockBackendInterface $lock
   *   The lock backend.
   */
  public function __construct(ConfigFactoryInterface $config_factory, UserDataInterface $user_data, TimeInterface $time, LockBackendInterface $lock) {
    $this->configFactory = $config_factory;
    $this->config = $config_factory->get('webauthn.settings');
    $this->userData = $user_data;
    $this->clock = new TotpClock($time);
    $this->lock = $lock;
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
    $totp = TOTP::createFromSecret($secret, $this->clock);
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
   * Finds the time step a TOTP code belongs to.
   *
   * @param string $secret
   *   Base32-encoded TOTP secret.
   * @param string $code
   *   The 6-digit code entered by the user.
   *
   * @return int|null
   *   The matching time step, or NULL if the code is not valid now.
   */
  protected function matchTimeStep(string $secret, string $code): ?int {
    $totp = TOTP::createFromSecret($secret, $this->clock);
    $now = $this->clock->now()->getTimestamp();
    foreach ([$now - self::LEEWAY, $now, $now + self::LEEWAY] as $timestamp) {
      if (hash_equals($totp->at($timestamp), $code)) {
        return intdiv($timestamp - $totp->getEpoch(), $totp->getPeriod());
      }
    }
    return NULL;
  }

  /**
   * Verifies a 6-digit TOTP code against a secret.
   *
   * Does not prevent replay; use verifyAndConsume() when authenticating.
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
    return $this->matchTimeStep($secret, $code) !== NULL;
  }

  /**
   * Verifies a code and marks its time step as used for the user.
   *
   * A code is accepted only if its time step is later than the last one
   * accepted for this user, so each code can be used once (RFC 6238 5.2).
   *
   * @param int $uid
   *   Drupal user ID.
   * @param string $secret
   *   Base32-encoded TOTP secret.
   * @param string $code
   *   The 6-digit code entered by the user.
   *
   * @return bool
   *   TRUE if the code is valid and was not used before.
   */
  public function verifyAndConsume(int $uid, string $secret, string $code): bool {
    $step = $this->matchTimeStep($secret, $code);
    if ($step === NULL) {
      return FALSE;
    }
    // Serialize per user without waiting: a concurrent attempt simply fails.
    $lock_name = 'webauthn_totp_step:' . $uid;
    if (!$this->lock->acquire($lock_name, 5)) {
      return FALSE;
    }
    try {
      $last = $this->userData->get('webauthn', $uid, 'totp_last_step');
      if ($last !== NULL && $step <= (int) $last) {
        return FALSE;
      }
      $this->userData->set('webauthn', $uid, 'totp_last_step', $step);
      return TRUE;
    }
    finally {
      $this->lock->release($lock_name);
    }
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
