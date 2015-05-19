Cliente OpenID Connect PHP 5
============================
Esta libreria permite que una aplicación autentique a un usuario a traves del protocolo OpenID Connect.

# Requerimientos
 1. PHP 5.2 or greater 
 2. CURL extension
 3. JSON extension

## Ejemplo

```php
$oidc = new OpenIDConnectClient('https://id.buenosaires.gob.ar/openid',
                                'client-id',
                                'client-secret');

$oidc->authenticate();

$email = $oidc->requestUserInfo('email');
```

Basado en [jumbojett/OpenID-Connect-PHP](https://github.com/jumbojett/OpenID-Connect-PHP).