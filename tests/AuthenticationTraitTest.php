<?php

namespace Tests\sblum\TestTraits;

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

        /** @var Session $session */
        $session = $client->getContainer()->get('session');
        /** @var TokenInterface $token */
        $token = \unserialize(
            $session->get('_security_main')
        );

        $this->assertInstanceOf(UsernamePasswordToken::class, $token);
        $this->assertSame('my-username', $token->getUsername());
        $this->assertEquals([new Role('ROLE_ADMIN')], $token->getRoles());
    }
}
