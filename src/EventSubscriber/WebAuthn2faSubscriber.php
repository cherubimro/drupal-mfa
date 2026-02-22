<?php

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
   * @var \Drupal\Core\Session\AccountProxyInterface
   */
  protected $currentUser;

  /**
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

  /**
   * Routes that are allowed while 2FA is pending.
   */
  protected static $allowedRoutes = [
    'webauthn.verify',
    'webauthn.assert_options',
    'webauthn.assert_verify',
    'webauthn.totp_verify',
    'user.logout',
  ];

  /**
   * Constructs the subscriber.
   */
  public function __construct(AccountProxyInterface $current_user, ConfigFactoryInterface $config_factory) {
    $this->currentUser = $current_user;
    $this->configFactory = $config_factory;
  }

  /**
   * Redirects to verification page if 2FA is pending.
   */
  public function onKernelRequest(RequestEvent $event) {
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
  public static function getSubscribedEvents() {
    // Priority 30: after authentication (300+) and after maintenance mode (31).
    $events[KernelEvents::REQUEST][] = ['onKernelRequest', 30];
    return $events;
  }

}
