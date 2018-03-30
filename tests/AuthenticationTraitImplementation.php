<?php

namespace Tests\SBlum\TestTraits;

use SBlum\TestTraits\AuthenticationTrait;
use Symfony\Bundle\FrameworkBundle\Client;

class AuthenticationTraitImplementation
{
    use AuthenticationTrait;

    public function delegateLogIn(Client $client, string $username, array $roles)
    {
        $this->logIn($client, $username, $roles);
    }

    public function delegateLogInAsAdmin(Client $client)
    {
        $this->logInAsAdmin($client);
    }

    public function delegateLogInAsSuperAdmin(Client $client)
    {
        $this->logInAsSuperAdmin($client);
    }

    public function delegateLogInAsUser(Client $client)
    {
        $this->logInAsUser($client);
    }

    public function delegateSetFirewall(string $firewall)
    {
        $this->setFirewall($firewall);
    }
}
