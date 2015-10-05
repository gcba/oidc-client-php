<?php

/**
 *
 * Copyright MITRE 2012
 *
 * OpenIDConnectClient for PHP5
 * Author: Michael Jett <mjett@mitre.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 */

require "OpenIDConnectClient.php5";

$oidc = new OpenIDConnectClient('https://provider.com/openid',
                                'client_id',
                                'secret_id');

$oidc->addScope("openid email profile address phone");
$oidc->authenticate();
$email = $oidc->requestUserInfo('email');
$given_name = $oidc->requestUserInfo('given_name');
$address = $oidc->requestUserInfo('address');
?>

<html>
<head>
    <title>Ejemplo del Cliente OpenID Connect</title>
    <style>
        body {
            font-family: 'Lucida Grande', Verdana, Arial, sans-serif;
        }
    </style>
</head>
<body>

    <div>
        Hola <?php echo $given_name; ?><br>
        Tu correo electrónico es <?php echo $email; ?><br>
        Tu domicilio es <?php echo $address->street_address; ?><br>
        Tu codigo postal es <?php echo $address->postal_code; ?>
    </div>

</body>
</html>
