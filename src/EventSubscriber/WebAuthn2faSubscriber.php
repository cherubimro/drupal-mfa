<?php

declare(strict_types=1);

namespace Drupal\webauthn\EventSubscriber;

use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\Url;
use Drupal\webauthn\DestinationHelper;
use Drupal\webauthn\Exception\TwoFactorRequiredException;
use Drupal\webauthn\Service\WebAuthnManager;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Enforces 2FA for authenticated requests.
 *
 * Fails closed: a user who needs 2FA is only let through when their session
 * has completed it (or does not need it). Session logins that have not yet
 * completed 2FA are redirected to the verification page; requests
 * authenticated without a Drupal session (e.g. HTTP Basic, token providers)
 * are denied.
 */
class WebAuthn2faSubscriber implements EventSubscriberInterface {

  /**
   * The current user.
   *
   * @var \Drupal\Core\Session\AccountProxyInterface
   */
  protected AccountProxyInterface $currentUser;

  /**
   * The WebAuthn manager.
   *
   * @var \Drupal\webauthn\Service\WebAuthnManager
   */
  protected WebAuthnManager $webauthnManager;

  /**
   * Routes reachable while 2FA is pending.
   *
   * Besides the verification ceremony and logout, static assets must stay
   * reachable so the verification page's JavaScript can load.
   *
   * @var string[]
   */
  protected static array $allowedRoutes = [
    'webauthn.verify',
    'webauthn.assert_options',
    'webauthn.assert_verify',
    'webauthn.totp_verify',
    'webauthn.totp_verify_api',
    'user.logout',
    'user.logout.confirm',
    'user.logout.http',
    'system.css_asset',
    'system.js_asset',
    // So a client that lost its token can obtain one without being redirected
    // to a page it cannot render.
    'system.csrftoken',
  ];

  /**
   * Constructs the subscriber.
   *
   * @param \Drupal\Core\Session\AccountProxyInterface $current_user
   *   The current user.
   * @param \Drupal\webauthn\Service\WebAuthnManager $webauthn_manager
   *   The WebAuthn manager.
   */
  public function __construct(AccountProxyInterface $current_user, WebAuthnManager $webauthn_manager) {
    $this->currentUser = $current_user;
    $this->webauthnManager = $webauthn_manager;
  }

  /**
   * Redirects to verification, or denies access, until 2FA is complete.
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   The kernel request event.
   */
  public function onKernelRequest(RequestEvent $event): void {
    if (!$event->isMainRequest()) {
      return;
    }
    $request = $event->getRequest();
    if ($this->currentUser->isAnonymous()) {
      return;
    }

    $uid = (int) $this->currentUser->id();
    $session = $request->hasSession() ? $request->getSession() : NULL;
    // The user was authenticated from this Drupal session (cookie), rather
    // than from per-request credentials such as HTTP Basic.
    $session_login = $session && (int) $session->get('uid') === $uid;

    // Already completed 2FA in this session.
    if ($session_login && $session->get('webauthn_2fa_ok') === $uid) {
      return;
    }

    // Re-evaluated every request until completed, so dropping the requirement
    // (policy change, methods removed) releases a pending session.
    if (!$this->webauthnManager->should2fa($uid)) {
      if ($session_login) {
        $session->remove('webauthn_2fa_pending');
        $session->set('webauthn_2fa_ok', $uid);
      }
      return;
    }

    if (!$session_login) {
      throw new TwoFactorRequiredException('Two-factor authentication is required for this account.');
    }

    // Mark the session pending and, once, remember the originally requested
    // page (e.g. the one-time login / password reset form) to return to.
    if (!$session->get('webauthn_2fa_pending')) {
      $session->set('webauthn_2fa_pending', TRUE);
      $session->remove('webauthn_mfa_completed');
      $session->remove('webauthn_2fa_destination');
      if ($request->isMethod('GET') && !$this->isAllowedRoute($request)
        && ($destination = DestinationHelper::localPath($request->getRequestUri()))) {
        $session->set('webauthn_2fa_destination', $destination);
      }
    }

    if ($this->isAllowedRoute($request)) {
      return;
    }

    // A client that cannot render the verification page is told what it needs
    // in its own format, rather than redirected to HTML.
    if ($request->getRequestFormat() !== 'html') {
      $event->setResponse($this->verificationRequiredResponse($request));
      return;
    }

    $event->setResponse(new RedirectResponse(Url::fromRoute('webauthn.verify')->toString()));
  }

  /**
   * Keeps error pages from rendering in a pending session's context.
   *
   * Routing failures (404/403/405, CSRF, method) throw before the request
   * gate runs, and core renders the error page in a sub-request that is still
   * authenticated as the user. Answer those without rendering the themed page,
   * which would disclose account-specific content (toolbar, blocks, roles).
   *
   * @param \Symfony\Component\HttpKernel\Event\ExceptionEvent $event
   *   The kernel exception event.
   */
  public function onKernelException(ExceptionEvent $event): void {
    if (!$event->isMainRequest() || $event->hasResponse()) {
      return;
    }
    $request = $event->getRequest();
    $exception = $event->getThrowable();

    // Our own denial of a request that cannot complete 2FA (no Drupal
    // session): answer it unthemed, so nothing is rendered as the user.
    if ($exception instanceof TwoFactorRequiredException) {
      $event->setResponse($this->deniedResponse($request, $exception->getMessage()));
      return;
    }

    // Anything else: only client errors, so server errors keep their normal
    // handling and logging.
    if (!$exception instanceof HttpExceptionInterface
      || $exception->getStatusCode() < 400 || $exception->getStatusCode() > 499) {
      return;
    }
    if ($this->currentUser->isAnonymous() || $this->isAllowedRoute($request)) {
      return;
    }

    $uid = (int) $this->currentUser->id();
    $session = $request->hasSession() ? $request->getSession() : NULL;
    if (!$session || (int) $session->get('uid') !== $uid) {
      return;
    }
    if ($session->get('webauthn_2fa_ok') === $uid || !$this->webauthnManager->should2fa($uid)) {
      return;
    }

    // Non-HTML clients cannot complete the ceremony, so answer them in their
    // own format rather than redirecting them to a page.
    if ($request->getRequestFormat() !== 'html') {
      $event->setResponse($this->verificationRequiredResponse($request));
      return;
    }

    $event->setResponse(new RedirectResponse(Url::fromRoute('webauthn.verify')->toString()));
  }

  /**
   * Builds a response telling a non-HTML client that verification is needed.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   A 403 naming the endpoint where the second factor can be submitted.
   */
  protected function verificationRequiredResponse(Request $request): Response {
    if ($request->getRequestFormat() === 'html') {
      return $this->deniedResponse($request, 'Two-factor verification is required.');
    }
    return new JsonResponse([
      'message' => 'Two-factor verification is required before this request can be completed.',
      'verification_required' => TRUE,
      'verify_url' => Url::fromRoute('webauthn.totp_verify_api')->toString(),
    ], 403);
  }

  /**
   * Builds an unthemed 403 for a request that cannot complete 2FA.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   * @param string $message
   *   The message to return.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   A 403 response that renders no account-specific content.
   */
  protected function deniedResponse(Request $request, string $message): Response {
    if ($request->getRequestFormat() !== 'html') {
      return new JsonResponse(['message' => $message], 403);
    }
    return new Response('<!DOCTYPE html><html><head><title>Access denied</title></head><body><p>'
      . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</p></body></html>', 403,
      ['Content-Type' => 'text/html; charset=UTF-8']);
  }

  /**
   * Checks whether the request's route may be reached while 2FA is pending.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   *
   * @return bool
   *   TRUE if the route is on the allow-list.
   */
  protected function isAllowedRoute(Request $request): bool {
    return in_array($request->attributes->get('_route'), static::$allowedRoutes, TRUE);
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    // Priority 30: after authentication (300+) and maintenance mode (31).
    $events[KernelEvents::REQUEST][] = ['onKernelRequest', 30];
    // Priority 40: after core's exception logging (50) so errors are still
    // recorded, before the CSRF confirm redirect (0) and the HTML error-page
    // renderers (<= 0).
    $events[KernelEvents::EXCEPTION][] = ['onKernelException', 40];
    return $events;
  }

}
