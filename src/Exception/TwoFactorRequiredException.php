<?php

declare(strict_types=1);

namespace Drupal\webauthn\Exception;

use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * Thrown when a request cannot satisfy the account's 2FA requirement.
 *
 * Raised for requests authenticated without a Drupal session (e.g. HTTP Basic
 * or token providers). It is answered with an unthemed response, so no
 * account-specific content is rendered for the denied request.
 */
class TwoFactorRequiredException extends AccessDeniedHttpException {

}
