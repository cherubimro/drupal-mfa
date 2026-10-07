<?php

declare(strict_types=1);

namespace Drupal\webauthn;

use Drupal\Component\Utility\UrlHelper;

/**
 * Validates post-verification redirect destinations.
 *
 * The destination is followed by JavaScript (window.location), so core's
 * redirect response checks do not apply. Only local paths are accepted.
 */
final class DestinationHelper {

  /**
   * Returns the destination if it is a safe local path, NULL otherwise.
   *
   * @param mixed $destination
   *   The candidate destination, e.g. from the 'destination' query parameter.
   *
   * @return string|null
   *   The destination, or NULL if it is not a local path.
   */
  public static function localPath(mixed $destination): ?string {
    if (!is_string($destination) || $destination === '') {
      return NULL;
    }
    // Must be a path on this site: a single leading slash. This rejects
    // scheme URLs such as javascript: or data:, which UrlHelper::isExternal()
    // does not report as external.
    if ($destination[0] !== '/') {
      return NULL;
    }
    // Browsers drop tabs and newlines while parsing URLs, so "/\t/host"
    // becomes "//host"; reject all control and invisible characters.
    if (preg_match('/\p{C}/u', $destination) !== 0) {
      return NULL;
    }
    // Rejects "//host" and "/\host" (backslashes are normalized).
    if (UrlHelper::isExternal($destination)) {
      return NULL;
    }
    return $destination;
  }

}
