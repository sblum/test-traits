<?php

namespace Tests\SBlum\TestTraits;

use Symfony\Bundle\FrameworkBundle\Client;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Role\Role;

class AuthenticationTraitTest extends WebTestCase
{
    public function testAuthenticationTrait()
    {
        $implementation = new AuthenticationTraitImplementation();

        $this->assertTrue(\method_exists($implementation, 'logIn'));
        $this->assertTrue(\method_exists($implementation, 'logInAsUser'));
        $this->assertTrue(\method_exists($implementation, 'logInAsAdmin'));
        $this->assertTrue(\method_exists($implementation, 'logInAsSuperAdmin'));
    }

    public function testLogIn()
    {
        $client = static::createClient();

        $implementation = new AuthenticationTraitImplementation();
        $implementation->delegateLogIn(
            $client,
            'my-username',
            ['ROLE_ADMIN']
        );

        $token = $this->generateToken($client);
        $this->assertInstanceOf(UsernamePasswordToken::class, $token);
        $this->assertSame('my-username', $token->getUsername());
        $this->assertEquals([new Role('ROLE_ADMIN')], $token->getRoles());
    }

    public function testLoginAsAdmin()
    {
        $client = static::createClient();

        $implementation = new AuthenticationTraitImplementation();
        $implementation->delegateLogInAsAdmin($client);

        $token = $this->generateToken($client);
        $this->assertInstanceOf(UsernamePasswordToken::class, $token);
        $this->assertSame('admin', $token->getUsername());
        $this->assertEquals([new Role('ROLE_ADMIN')], $token->getRoles());
    }

    public function testLoginAsSuperAdmin()
    {
        $client = static::createClient();

        $implementation = new AuthenticationTraitImplementation();
        $implementation->delegateLogInAsSuperAdmin($client);

        $token = $this->generateToken($client);
        $this->assertInstanceOf(UsernamePasswordToken::class, $token);
        $this->assertSame('superadmin', $token->getUsername());
        $this->assertEquals([new Role('ROLE_SUPER_ADMIN')], $token->getRoles());
    }

    public function testLoginAsUser()
    {
        $client = static::createClient();

        $implementation = new AuthenticationTraitImplementation();
        $implementation->delegateLogInAsAdmin($client);

        $token = $this->generateToken($client);
        $this->assertInstanceOf(UsernamePasswordToken::class, $token);
        $this->assertSame('admin', $token->getUsername());
        $this->assertEquals([new Role('ROLE_ADMIN')], $token->getRoles());
    }

    public function testSetFirewall()
    {
        $implementation = new AuthenticationTraitImplementation();
        $implementation->delegateSetFirewall('my-firewall');

        $this->assertAttributeSame('my-firewall', 'firewall', $implementation);
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
