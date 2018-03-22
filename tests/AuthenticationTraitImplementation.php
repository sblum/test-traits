<?php

namespace Tests\sblum\TestTraits;

use sblum\TestTraits\AuthenticationTrait;
use Symfony\Bundle\FrameworkBundle\Client;

class AuthenticationTraitImplementation
{
    use AuthenticationTrait;

    public function delegateLogIn(Client $client, string $username, array $roles)
    {
        $this->logIn($client, $username, $roles);
    }
}
