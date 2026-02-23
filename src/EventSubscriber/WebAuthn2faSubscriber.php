<?php

declare(strict_types=1);

namespace Drupal\webauthn\EventSubscriber;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\Url;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Redirects authenticated users with pending 2FA to the verification page.
 */
class WebAuthn2faSubscriber implements EventSubscriberInterface {

  /**
   * The current user.
   *
   * @var \Drupal\Core\Session\AccountProxyInterface
   */
  protected AccountProxyInterface $currentUser;

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected ConfigFactoryInterface $configFactory;

  /**
   * Routes that are allowed while 2FA is pending.
   *
   * @var string[]
   */
  protected static array $allowedRoutes = [
    'webauthn.verify',
    'webauthn.assert_options',
    'webauthn.assert_verify',
    'webauthn.totp_verify',
    'user.logout',
  ];

  /**
   * Constructs the subscriber.
   *
   * @param \Drupal\Core\Session\AccountProxyInterface $current_user
   *   The current user.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   */
  public function __construct(AccountProxyInterface $current_user, ConfigFactoryInterface $config_factory) {
    $this->currentUser = $current_user;
    $this->configFactory = $config_factory;
  }

  /**
   * Redirects to verification page if 2FA is pending.
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   The kernel request event.
   */
  public function onKernelRequest(RequestEvent $event): void {
    if (method_exists($event, 'isMainRequest') ? !$event->isMainRequest() : !$event->isMasterRequest()) {
      return;
    }

    // Anonymous users don't need 2FA gate.
    if ($this->currentUser->isAnonymous()) {
      return;
    }

    $request = $event->getRequest();
    $session = $request->getSession();

    if (!$session || !$session->get('webauthn_2fa_pending')) {
      return;
    }

    // Check if current route is allowed.
    $route_name = $request->attributes->get('_route');
    if (in_array($route_name, static::$allowedRoutes, TRUE)) {
      return;
    }

    // Redirect to verification page.
    $url = Url::fromRoute('webauthn.verify')->toString();
    $event->setResponse(new RedirectResponse($url));
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    // Priority 30: after authentication (300+) and after maintenance mode (31).
    $events[KernelEvents::REQUEST][] = ['onKernelRequest', 30];
    return $events;
  }

}
