Cliente OpenID Connect PHP 5
============================
Esta libreria permite que una aplicación identifiqué a un usuario a través del protocolo OpenID Connect.

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

En el ejemplo obtenemos el `email`, pero tambíen se pueden traer otros campos. El listado completo se encuentra [aquí](http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims).


Basado en [jumbojett/OpenID-Connect-PHP](https://github.com/jumbojett/OpenID-Connect-PHP).
