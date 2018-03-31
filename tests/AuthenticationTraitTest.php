<?php

namespace Tests\SBlum\TestTraits;

use SBlum\TestTraits\AuthenticationTrait;
use Symfony\Bundle\FrameworkBundle\Client;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\Container;
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
        $redirectResponse = new RedirectResponse('/custom-login');

        /** @var Client $client */
        $client = $this->createMock(Client::class);
        $client
            ->expects($this->atLeastOnce())
            ->method('getResponse')
            ->willReturn($redirectResponse);

        $this->assertAccessDenied($client, '/custom-login');
    }

    public function testAssertAccessDeniedWithGuessedLogInPath(): void
    {
        $redirectResponse = new RedirectResponse('/login');

        /** @var Container $container */
        $container = $this->createMock(Container::class);
        $container
            ->expects($this->once())
            ->method('hasParameter')
            ->with($this->identicalTo('security.access.denied_url'))
            ->willReturn(true);
        $container
            ->expects($this->once())
            ->method('getParameter')
            ->with($this->identicalTo('security.access.denied_url'))
            ->willReturn('/login');

        /** @var Client $client */
        $client = $this->createMock(Client::class);
        $client
            ->expects($this->atLeastOnce())
            ->method('getResponse')
            ->willReturn($redirectResponse);
        $client
            ->expects($this->atLeastOnce())
            ->method('getContainer')
            ->willReturn($container);

        $this->assertAccessDenied($client);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage LogInPath cannot be null if symfony/security-bundle is not installed.
     */
    public function testAssertAccessDeniedUrlDoesNotExist()
    {
        $redirectResponse = new RedirectResponse('/login');

        /** @var Container $container */
        $container = $this->createMock(Container::class);
        $container
            ->expects($this->once())
            ->method('hasParameter')
            ->with($this->identicalTo('security.access.denied_url'))
            ->willReturn(false);

        /** @var Client $client */
        $client = $this->createMock(Client::class);
        $client
            ->expects($this->atLeastOnce())
            ->method('getResponse')
            ->willReturn($redirectResponse);
        $client
            ->expects($this->atLeastOnce())
            ->method('getContainer')
            ->willReturn($container);

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
