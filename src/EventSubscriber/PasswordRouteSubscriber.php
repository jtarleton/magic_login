<?php

declare(strict_types=1);

namespace Drupal\magic_login\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Hides core's password reset (/user/password) behind ?showcore=1.
 *
 * Sign-in is by emailed link; password reset is part of the core login that
 * only admins are told about. Answers 404, not 403, so the page does not
 * advertise itself. Covers the JSON variant (user.pass.http) too.
 */
final class PasswordRouteSubscriber implements EventSubscriberInterface {

  private const ROUTES = ['user.pass', 'user.pass.http'];

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    // After the router (32) has set _route.
    return [KernelEvents::REQUEST => ['onRequest', 31]];
  }

  /**
   * Hides the password routes unless the core login was asked for.
   */
  public function onRequest(RequestEvent $event): void {
    $request = $event->getRequest();
    if (!in_array($request->attributes->get('_route'), self::ROUTES, TRUE)) {
      return;
    }
    if (!\Drupal::config('magic_login.settings')->get('login_form_integration')) {
      return;
    }
    if (!magic_login_show_core()) {
      throw new NotFoundHttpException();
    }
  }

}
