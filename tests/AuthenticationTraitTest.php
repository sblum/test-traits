<?php

namespace Tests\SBlum\TestTraits;

use SBlum\TestTraits\AuthenticationTrait;
use Symfony\Bundle\FrameworkBundle\Client;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Role\Role;

class AuthenticationTraitTest extends WebTestCase
{
    use AuthenticationTrait;

    public function testAuthenticationTrait(): void
    {
        $this->assertTrue(\method_exists($this, 'assertAccessDenied'));
        $this->assertTrue(\method_exists($this, 'logIn'));
        $this->assertTrue(\method_exists($this, 'logInAsUser'));
        $this->assertTrue(\method_exists($this, 'logInAsAdmin'));
        $this->assertTrue(\method_exists($this, 'logInAsSuperAdmin'));
    }

    public function testAssertAccessDeniedWithLogInPath(): void
    {
        $this->setLogInPath('/my-login');
        $redirectResponse = new RedirectResponse('/my-login');

        /** @var Client $client */
        $client = $this->createMock(Client::class);
        $client
            ->expects($this->atLeastOnce())
            ->method('getResponse')
            ->willReturn($redirectResponse);

        $this->assertAccessDenied($client);
    }

    public function testLogIn(): void
    {
        $client = static::createClient();

        $this->logIn(
            $client,
            'my-username',
            ['ROLE_ADMIN']
        );

        $token = $this->generateToken($client);
        $this->assertInstanceOf(UsernamePasswordToken::class, $token);
        $this->assertSame('my-username', $token->getUsername());
        $this->assertEquals([new Role('ROLE_ADMIN')], $token->getRoles());
    }

    public function testLoginAsAdmin(): void
    {
        $client = static::createClient();

        $this->logInAsAdmin($client);

        $token = $this->generateToken($client);
        $this->assertInstanceOf(UsernamePasswordToken::class, $token);
        $this->assertSame('admin', $token->getUsername());
        $this->assertEquals([new Role('ROLE_ADMIN')], $token->getRoles());
    }

    public function testLoginAsSuperAdmin(): void
    {
        $client = static::createClient();

        $this->logInAsSuperAdmin($client);

        $token = $this->generateToken($client);
        $this->assertInstanceOf(UsernamePasswordToken::class, $token);
        $this->assertSame('superadmin', $token->getUsername());
        $this->assertEquals([new Role('ROLE_SUPER_ADMIN')], $token->getRoles());
    }

    public function testLoginAsUser(): void
    {
        $client = static::createClient();

        $this->logInAsUser($client);

        $token = $this->generateToken($client);
        $this->assertInstanceOf(UsernamePasswordToken::class, $token);
        $this->assertSame('user', $token->getUsername());
        $this->assertEquals([new Role('ROLE_USER')], $token->getRoles());
    }

    public function testSetFirewall(): void
    {
        $this->setFirewall('my-firewall');
        $this->assertAttributeSame('my-firewall', 'firewall', $this);
    }

    public function testSetLogInPath(): void
    {
        $this->setLogInPath('/my/login-path');
        $this->assertAttributeSame('/my/login-path', 'logInPath', $this);
    }

    private function generateToken(Client $client, string $firewall = 'main'): TokenInterface
    {
        /** @var Session $session */
        $session = $client->getContainer()->get('session');

        /** @var TokenInterface $token */
        $token = \unserialize(
            $session->get(\sprintf('_security_%s', $firewall))
        );

        return $token;
    }
}
