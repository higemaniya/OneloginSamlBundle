<?php

namespace Hslavich\OneloginSamlBundle\Security\Firewall;

use Hslavich\OneloginSamlBundle\Security\Authentication\Token\SamlToken;
use Hslavich\OneloginSamlBundle\Security\Authentication\Token\SamlTokenFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;

class SamlListener extends AbstractAuthenticationListener
{
    /**
     * @var \OneLogin_Saml2_Auth
     */
    protected $oneLoginAuth;
    protected $tokenFactory;

    /**
     * @param \OneLogin_Saml2_Auth $oneLoginAuth
     */
    public function setOneLoginAuth(\OneLogin_Saml2_Auth $oneLoginAuth)
    {
        $this->oneLoginAuth = $oneLoginAuth;
    }

    /**
     * @param SamlTokenFactoryInterface $tokenFactory
     */
    public function setTokenFactory(SamlTokenFactoryInterface $tokenFactory)
    {
        $this->tokenFactory = $tokenFactory;
    }

    /**
     * Performs authentication.
     *
     * @param Request $request A Request instance
     * @return TokenInterface|Response|null The authenticated token, null if full authentication is not possible, or a Response
     *
     * @throws AuthenticationException if the authentication fails
     * @throws \Exception if attribute set by "username_attribute" option not found
     */
    protected function attemptAuthentication(Request $request)
    {
        $this->oneLoginAuth->processResponse();
        if ($this->oneLoginAuth->getErrors()) {
            $this->logger->error($this->oneLoginAuth->getLastErrorReason());
            throw new AuthenticationException($this->oneLoginAuth->getLastErrorReason());
        }

        $attributes = $this->oneLoginAuth->getAttributes();
        $attributes['sessionIndex'] = $this->oneLoginAuth->getSessionIndex();

        if (isset($this->options['username_attribute'])) {
            if (!array_key_exists($this->options['username_attribute'], $attributes)) {
                $this->logger->error(sprintf("Found attributes: %s", print_r($attributes, true)));
                throw new \Exception(sprintf("Attribute '%s' not found in SAML data", $this->options['username_attribute']));
            }

            $username = $attributes[$this->options['username_attribute']][0];
        } else {
            $username = $this->oneLoginAuth->getNameId();
        }
        $token = $this->tokenFactory->createToken($username, $attributes, array());

        return $this->authenticationManager->authenticate($token);
    }
}
