<?php

namespace SBlum\TestTraits;

use Symfony\Bundle\FrameworkBundle\Client;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

trait AuthenticationTrait
{
    private $firewall = 'main';
    private $logInPath = null;

    /**
     * @param Client $client
     */
    private function assertAccessDenied(Client $client): void
    {
        $this->assertSame(
            Response::HTTP_FOUND,
            $client->getResponse()->getStatusCode(),
            \sprintf('AccessDenied redirects to the login page, so status code 302 was expected. Got: "%d"', $client->getResponse()->getStatusCode())
        );

        if (!empty($this->logInPath)) {
            $logInPath = $this->logInPath;
        }

        $this->assertTrue(
            $client->getResponse()->isRedirect($logInPath),
            \sprintf('Expected login path is "%s", but got: "%s"', $logInPath, $client->getResponse()->headers->get('Location'))
        );
    }

    /**
     * @param Client $client
     * @param string $username
     * @param array  $roles
     */
    private function logIn(Client &$client, string $username, array $roles): void
    {
        /** @var Session $session */
        $session = $client->getContainer()->get('session');

        $token = new UsernamePasswordToken($username, null, $this->firewall, $roles);
        $session->set('_security_'.$this->firewall, \serialize($token));
        $session->save();

        $cookie = new Cookie($session->getName(), $session->getId());
        $client->getCookieJar()->set($cookie);
    }

    /**
     * @param Client $client
     */
    private function logInAsAdmin(Client &$client): void
    {
        $this->logIn($client, 'admin', ['ROLE_ADMIN']);
    }

    /**
     * @param Client $client
     */
    private function logInAsSuperAdmin(Client &$client): void
    {
        $this->logIn($client, 'superadmin', ['ROLE_SUPER_ADMIN']);
    }

    /**
     * @param Client $client
     */
    private function logInAsUser(Client &$client): void
    {
        $this->logIn($client, 'user', ['ROLE_USER']);
    }

    /**
     * @param string $firewall
     */
    private function setFirewall(string $firewall): void
    {
        $this->firewall = $firewall;
    }

    private function setLogInPath(string $logInPath): void
    {
        $this->logInPath = $logInPath;
    }
}
