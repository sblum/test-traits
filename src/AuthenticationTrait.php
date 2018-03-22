<?php

namespace sblum\TestTraits;

use Symfony\Bundle\FrameworkBundle\Client;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

trait AuthenticationTrait
{
    private $firewall = 'main';

    protected function setFirewall(string $firewall)
    {
        $this->firewall = $firewall;
    }

    protected function logInAsAdmin(Client &$client)
    {
        $this->logIn($client, 'admin', ['ROLE_ADMIN']);
    }

    protected function logInAsSuperAdmin(Client &$client)
    {
        $this->logIn($client, 'superadmin', ['ROLE_SUPER_ADMIN']);
    }

    protected function logInAsUser(Client &$client)
    {
        $this->logIn($client, 'user', ['ROLE_USER']);
    }

    protected function logIn(Client &$client, string $username, array $roles)
    {
        /** @var Session $session */
        $session = $client->getContainer()->get('session');

        $token = new UsernamePasswordToken($username, null, $this->firewall, $roles);
        $session->set('_security_'.$this->firewall, \serialize($token));
        $session->save();

        $cookie = new Cookie($session->getName(), $session->getId());
        $client->getCookieJar()->set($cookie);
    }

    protected function assertAccessDenied(Client $client)
    {
        $this->assertTrue($client->getResponse()->isRedirect(), \sprintf('Status-Code war %s anstatt 302', $client->getResponse()->getStatusCode()));
        $this->assertContains('/login', $client->getResponse()->headers->get('Location'));
    }
}
