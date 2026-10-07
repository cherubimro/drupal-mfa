<?php

declare(strict_types=1);

namespace Drupal\webauthn\Service;

use Drupal\Component\Datetime\TimeInterface;
use Psr\Clock\ClockInterface;

/**
 * PSR-20 clock backed by Drupal's time service, for the OTP library.
 */
class TotpClock implements ClockInterface {

  /**
   * The time service.
   *
   * @var \Drupal\Component\Datetime\TimeInterface
   */
  protected TimeInterface $time;

  /**
   * Constructs a TotpClock.
   *
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   */
  public function __construct(TimeInterface $time) {
    $this->time = $time;
  }

  /**
   * {@inheritdoc}
   */
  public function now(): \DateTimeImmutable {
    return (new \DateTimeImmutable())->setTimestamp($this->time->getCurrentTime());
  }

}
