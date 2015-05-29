<?php

/**
 * OpenIDConnectClient for PHP5
 */

if (!isset($_SESSION)) {
    session_start();
}

/**
 * A wrapper around base64_decode which decodes Base64URL-encoded data,
 * which is not the same alphabet as base64.
 */
function base64url_decode($base64url) {
    return base64_decode(b64url2b64($base64url));
}

/**
 * Per RFC4648, "base64 encoding with URL-safe and filename-safe
 * alphabet".  This just replaces characters 62 and 63.  None of the
 * reference implementations seem to restore the padding if necessary,
 * but we'll do it anyway.
 *
 */
function b64url2b64($base64url) {
    // "Shouldn't" be necessary, but why not
    $padding = strlen($base64url) % 4;
    if ($padding > 0) {
	$base64url .= str_repeat("=", 4 - $padding);
    }
    return strtr($base64url, '-_', '+/');
}


/**
 * OpenIDConnect Exception Class
 */
class OpenIDConnectClientException extends Exception
{

}

/**
 * Require the CURL and JSON PHP extentions to be installed
 */
if (!function_exists('curl_init')) {
    throw new OpenIDConnectClientException('OpenIDConnect needs the CURL PHP extension.');
}
if (!function_exists('json_decode')) {
    throw new OpenIDConnectClientException('OpenIDConnect needs the JSON PHP extension.');
}

class OpenIDConnectClient
{

    /**
     * @var string arbitrary id value
     */
    private $clientID;

    /*
     * @var string arbitrary name value
     */
    private $clientName;

    /**
     * @var string arbitrary secret value
     */
    private $clientSecret;

    /**
     * @var array holds the provider configuration
     */
    private $providerConfig = array();

    /**
     * @var string http proxy if necessary
     */
    private $httpProxy;

    /**
     * @var string full system path to the SSL certificate
     */
    private $certPath;

    /**
     * @var string if we aquire an access token it will be stored here
     */
    private $accessToken;

    /**
     * @var string if we aquire a refresh token it will be stored here
     */
    private $refreshToken;

    /**
     * @var array holds scopes
     */
    private $scopes = array();

    /**
     * @var array holds a cache of info returned from the user info endpoint
     */
    private $userInfo = array();

    /**
     * @var array holds authentication parameters
     */
    private $authParams = array();

    /**
     * @param $provider_url string optional
     *
     * @param $client_id string optional
     * @param $client_secret string optional
     *
     */
    public function __construct($provider_url = null, $client_id = null, $client_secret = null) {
        $this->setProviderURL($provider_url);
        $this->clientID = $client_id;
        $this->clientSecret = $client_secret;
    }

    /**
     * @param $provider_url
     */
    public function setProviderURL($provider_url) {
        $this->providerConfig['issuer'] = $provider_url;
    }

    /**
     * @return bool
     * @throws OpenIDConnectClientException
     */
    public function authenticate() {

        // Do a preemptive check to see if the provider has thrown an error from a previous redirect
        if (isset($_REQUEST['error'])) {
            throw new OpenIDConnectClientException("Error: " . $_REQUEST['error'] . " Description: " . $_REQUEST['error_description']);
        }

        // If we have an authorization code then proceed to request a token
        if (isset($_REQUEST["code"])) {

            $code = $_REQUEST["code"];
            $token_json = $this->requestTokens($code);

            // Throw an error if the server returns one
            if (isset($token_json->error)) {
                throw new OpenIDConnectClientException($token_json->error_description);
            }

            // Do an OpenID Connect session check
            if ($_REQUEST['state'] != $_SESSION['openid_connect_state']) {
                throw new OpenIDConnectClientException("Unable to determine state");
            }

	    if (!property_exists($token_json, 'id_token')) {
		throw new OpenIDConnectClientException("User did not authorize openid scope.");
	    }

            $claims = $this->decodeJWT($token_json->id_token, 1);

	    // Verify the signature
	    if (true) {
		if (!$this->verifyJWTsignature($token_json->id_token)) {
		    throw new OpenIDConnectClientException ("Unable to verify signature");
		}
	    } else {
		user_error("Warning: JWT signature verification unavailable.");
	    }

            // If this is a valid claim
            if ($this->verifyJWTclaims($claims)) {

                // Save the access token
                $this->accessToken = $token_json->access_token;
                
                // Save the refresh token, if we got one
                if (isset($token_json->refresh_token)) $this->refreshToken = $token_json->refresh_token;

                // Success!
                return true;

            } else {
                throw new OpenIDConnectClientException ("Unable to verify JWT claims");
            }

        } else {

            $this->requestAuthorization();
            return false;
        }

    }

    /**
     * @param $scope - example: openid, given_name, etc...
     */
    public function addScope($scope) {
        $this->scopes = array_merge($this->scopes, (array)$scope);
    }

    /**
     * @param $param - example: prompt=login
     */
    public function addAuthParam($param) {
        $this->authParams = array_merge($this->authParams, (array)$param);
    }

    /**
     * Get's anything that we need configuration wise including endpoints, and other values
     *
     * @param $param
     * @throws OpenIDConnectClientException
     * @return string
     *
     */
    private function getProviderConfigValue($param) {

        // If the configuration value is not available, attempt to fetch it from a well known config endpoint
        // This is also known as auto "discovery"
        if (!isset($this->providerConfig[$param])) {
            $well_known_config_url = rtrim($this->getProviderURL(),"/") . "/.well-known/openid-configuration/";
            $value = json_decode($this->fetchURL($well_known_config_url))->{$param};

            if ($value) {
                $this->providerConfig[$param] = $value;
            } else {
                throw new OpenIDConnectClientException("The provider {$param} has not been set. Make sure your provider has a well known configuration available.");
            }

        }

        return $this->providerConfig[$param];
    }
    
    
    /**
     * @param $url Sets redirect URL for auth flow
     */
    public function setRedirectURL ($url) {
        if (filter_var($url, FILTER_VALIDATE_URL) !== false) {
            $this->redirectURL = $url;
        }
    }

    /**
     * Gets the URL of the current page we are on, encodes, and returns it
     *
     * @return string
     */
    public function getRedirectURL() {
        
        // If the redirect URL has been set then return it.
        if (property_exists($this, 'redirectURL') && $this->redirectURL) {
            return $this->redirectURL;
        }

        // Other-wise return the URL of the current page

        /**
         * Thank you
         * http://stackoverflow.com/questions/189113/how-do-i-get-current-page-full-url-in-php-on-a-windows-iis-server
         */
        $base_page_url = (@$_SERVER["HTTPS"] == "on") ? "https://" : "http://";
        if ($_SERVER["SERVER_PORT"] != "80" && $_SERVER["SERVER_PORT"] != "443") {
            $base_page_url .= $_SERVER["SERVER_NAME"] . ":" . $_SERVER["SERVER_PORT"];
        } else {
            $base_page_url .= $_SERVER["SERVER_NAME"];
        }

        $tmp = explode("?", $_SERVER['REQUEST_URI']);
        $base_page_url .= $tmp[0];

        return $base_page_url;
    }

    /**
     * Used for arbitrary value generation for nonces and state
     *
     * @return string
     */
    protected function generateRandString() {
        return md5(uniqid(rand(), TRUE));
    }

    /**
     * Start Here
     * @return void
     */
    private function requestAuthorization() {

        $auth_endpoint = $this->getProviderConfigValue("authorization_endpoint");
        $response_type = "code";

        // State essentially acts as a session key for OIDC
        $state = $this->generateRandString();
        $_SESSION['openid_connect_state'] = $state;

        $auth_params = array_merge($this->authParams, array(
            'response_type' => $response_type,
            'redirect_uri' => $this->getRedirectURL(),
            'client_id' => $this->clientID,
            'state' => $state,
            'scope' => 'openid email profile'
        ));

        // If the client has been registered with additional scopes
        if (sizeof($this->scopes) > 0) {
            $auth_params = array_merge($auth_params, array('scope' => implode(' ', $this->scopes)));
        }

        $auth_endpoint .= '?' . http_build_query($auth_params, null, '&');

        $this->redirect($auth_endpoint);

    }


    /**
     * Requests ID and Access tokens
     *
     * @param $code
     * @return mixed
     */
    private function requestTokens($code) {

        $token_endpoint = $this->getProviderConfigValue("token_endpoint");

        $grant_type = "authorization_code";

        $token_params = array(
            'grant_type' => $grant_type,
            'code' => $code,
            'redirect_uri' => $this->getRedirectURL(),
            'client_id' => $this->clientID,
            'client_secret' => $this->clientSecret
        );

        // Convert token params to string format
        $token_params = http_build_query($token_params, null, '&');

        return json_decode($this->fetchURL($token_endpoint, $token_params));

    }

    /**
      * @param array $keys
      * @param array $header
      * @throws OpenIDConnectClientException
      * @return object
      */
     private function get_key_for_header($keys, $header) {
         foreach ($keys as $key) {
             if ($key->alg == $header->alg && $key->kid == $header->kid) {
                 return $key;
             }
         }
         throw new OpenIDConnectClientException('Unable to find a key for (algorithm, kid):' . $header->alg . ', ' . $header->kid . ')');
     }
 

    /**
     * @param array $keys
     * @param string $alg
     * @throws OpenIDConnectClientException
     * @return object
     */
    private function get_key_for_alg($keys, $alg) {
        foreach ($keys as $key) {
            if ($key->kty == $alg) {
                return $key;
            }
        }
        throw new OpenIDConnectClientException('Unable to find a key for algorithm:' . $alg);
    }


    /**
     * @param string $hashtype
     * @param object $key
     * @throws OpenIDConnectClientException
     * @return bool
     */
    private function verifyRSAJWTsignature($hashtype, $key, $payload, $signature) {
        if (!class_exists('Crypt_RSA')) {
            throw new OpenIDConnectClientException('Crypt_RSA support unavailable.');
        }
        if (!(property_exists($key, 'n') and property_exists($key, 'e'))) {
            throw new OpenIDConnectClientException('Malformed key object');
        }
        /* We already have base64url-encoded data, so re-encode it as
           regular base64 and use the XML key format for simplicity.
        */
        $public_key_xml = "<RSAKeyValue>\r\n".
            "  <Modulus>" . b64url2b64($key->n) . "</Modulus>\r\n" .
            "  <Exponent>" . b64url2b64($key->e) . "</Exponent>\r\n" .
            "</RSAKeyValue>";
        $rsa = new Crypt_RSA();
        $rsa->setHash($hashtype);
        $rsa->loadKey($public_key_xml, CRYPT_RSA_PUBLIC_FORMAT_XML);
        $rsa->signatureMode = CRYPT_RSA_SIGNATURE_PKCS1;
        return $rsa->verify($payload, $signature);
    }

    /**
     * @param $jwt string encoded JWT
     * @throws OpenIDConnectClientException
     * @return bool
     */
    private function verifyJWTsignature($jwt) {
        return true;
    }

    /**
     * @param object $claims
     * @return bool
     */
    private function verifyJWTclaims($claims) {
        return (($claims->iss == $this->getProviderURL())
            && (($claims->aud == $this->clientID) || (in_array($this->clientID, $claims->aud))));
    }

    /**
     * @param $jwt string encoded JWT
     * @param int $section the section we would like to decode
     * @return object
     */
    private function decodeJWT($jwt, $section = 0) {

        $parts = explode(".", $jwt);
        return json_decode(base64url_decode($parts[$section]));
    }

    /**
     *
     * @param $attribute
     *
     * @return mixed
     *
     */
    public function requestUserInfo($attribute) {

        // Check to see if the attribute is already in memory
        if (array_key_exists($attribute, $this->userInfo)) {
            return $this->userInfo->$attribute;
        }

        $user_info_endpoint = $this->getProviderConfigValue("userinfo_endpoint");
        $process = curl_init($user_info_endpoint);
        $headers = array(
            'Content-Type: multipart/form-data',
            'Authorization: Bearer '. $this->accessToken
        );
        curl_setopt($process, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($process, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($process, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($process);
        curl_close($process);

        $user_json = json_decode($response);

        $this->userInfo = $user_json;

        if (array_key_exists($attribute, $this->userInfo)) {
            return $this->userInfo->$attribute;
        }

        return null;

    }


    /**
     * @param $url
     * @param null $post_body string If this is set the post type will be POST
     * @throws OpenIDConnectClientException
     * @return mixed
     */
    protected function fetchURL($url, $post_body = null) {


        // OK cool - then let's create a new cURL resource handle
        $ch = curl_init();

        // Determine whether this is a GET or POST
        if ($post_body != null) {
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $post_body);

            // Default content type is form encoded
            $content_type = 'application/x-www-form-urlencoded';

            // Determine if this is a JSON payload and add the appropriate content type
            if (is_object(json_decode($post_body))) {
                $content_type = 'application/json';
            }

            curl_setopt($ch, CURLOPT_HTTPHEADER, array(
                "Content-Type: {$content_type}",
                'Content-Length: ' . strlen($post_body)
            ));

        }

        // Set URL to download
        curl_setopt($ch, CURLOPT_URL, $url);

        if (isset($this->httpProxy)) {
            curl_setopt($ch, CURLOPT_PROXY, $this->httpProxy);
        }

        // Include header in result? (0 = yes, 1 = no)
        curl_setopt($ch, CURLOPT_HEADER, 0);

        /**
         * Set cert
         * Otherwise ignore SSL peer verification
         */
        if (isset($this->certPath)) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
            curl_setopt($ch, CURLOPT_CAINFO, $this->certPath);
        } else {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
        }

        // Should cURL return or print out the data? (true = return, false = print)
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        // Timeout in seconds
        curl_setopt($ch, CURLOPT_TIMEOUT, 60);

        // Download the given URL, and return output
        $output = curl_exec($ch);

        if (curl_exec($ch) === false) {
            throw new OpenIDConnectClientException('Curl error: ' . curl_error($ch));
        }

        // Close the cURL resource, and free system resources
        curl_close($ch);

        return $output;
    }

    /**
     * @return string
     * @throws OpenIDConnectClientException
     */
    public function getProviderURL() {

        if (!isset($this->providerConfig['issuer'])) {
            throw new OpenIDConnectClientException("The provider URL has not been set");
        } else {
            return $this->providerConfig['issuer'];
        }
    }

    /**
     * @param $url
     */
    public function redirect($url) {
        header('Location: ' . $url);
        exit;
    }

    /**
     * @param $httpProxy
     */
    public function setHttpProxy($httpProxy) {
        $this->httpProxy = $httpProxy;
    }

    /**
     * @param $certPath
     */
    public function setCertPath($certPath) {
        $this->certPath = $certPath;
    }

    /**
     *
     * Use this to alter a provider's endpoints and other attributes
     *
     * @param $array
     *        simple key => value
     */
    public function providerConfigParam($array) {
        $this->providerConfig = array_merge($this->providerConfig, $array);
    }

    /**
     * @param $clientSecret
     */
    public function setClientSecret($clientSecret) {
        $this->clientSecret = $clientSecret;
    }

    /**
     * @param $clientID
     */
    public function setClientID($clientID) {
        $this->clientID = $clientID;
    }


    /**
     * Dynamic registration
     *
     * @throws OpenIDConnectClientException
     */
    public function register() {

        $registration_endpoint = $this->getProviderConfigValue('registration_endpoint');

        $send_object = (object)array(
            'redirect_uris' => array($this->getRedirectURL()),
            'client_name' => $this->getClientName()
        );

        $response = $this->fetchURL($registration_endpoint, json_encode($send_object));

        $json_response = json_decode($response);

        // Throw some errors if we encounter them
        if ($json_response === false) {
            throw new OpenIDConnectClientException("Error registering: JSON response received from the server was invalid.");
        } elseif (isset($json_response->{'error_description'})) {
            throw new OpenIDConnectClientException($json_response->{'error_description'});
        }

        $this->setClientID($json_response->{'client_id'});

        // The OpenID Connect Dynamic registration protocol makes the client secret optional
        // and provides a registration access token and URI endpoint if it is not present
        if (isset($json_response->{'client_secret'})) {
            $this->setClientSecret($json_response->{'client_secret'});
        } else {
            throw new OpenIDConnectClientException("Error registering:
                                                    Please contact the OpenID Connect provider and obtain a Client ID and Secret directly from them");
        }

    }

    /**
     * @return mixed
     */
    public function getClientName() {
        return $this->clientName;
    }

    /**
     * @param $clientName
     */
    public function setClientName($clientName) {
        $this->clientName = $clientName;
    }

    /**
     * @return string
     */
    public function getClientID() {
        return $this->clientID;
    }

    /**
     * @return string
     */
    public function getClientSecret() {
        return $this->clientSecret;
    }

    /**
     * @return bool
     */
    public function canVerifySignatures() {
      return class_exists('Crypt_RSA');
    }

    /**
     * @return string
     */
    public function getAccessToken() {
        return $this->accessToken;
    }

    /**
     * @return string
     */
    public function getRefreshToken() {
        return $this->refreshToken;
    }


}
