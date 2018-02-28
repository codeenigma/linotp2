<?php
/**
 * An authentication processing filter that allows you to use a device registered with
 * a LinOTP server as a second factor.
 * 
 * Most of this code is copied from the 'yubikey' module by 
 * Jaime Pérez Crespo, UNINETT AS <jaime.perez@uninett.no>
 *
 * @author Greg Harvey, Code Enigma <greg.harvey@codeenigma.com>
 * @package SimpleSAML\Module\linotp2
 */

class sspmod_linotp2_Auth_Process_OTP extends SimpleSAML_Auth_ProcessingFilter
{

	/**
	 * The URL of the LinOTP server
	 */
	private $linotpserver;
	
	/**
	 * The attribute we should use in the $state['Attributes'] array to look up LinOTP username
	 */
	private $linotpuidattribute;

	/**
	 * If the sslcert should be checked
	 */
	private $sslverifyhost;
	
	/**
	 * If the sslcert should be checked
	 */
	private $sslverifypeer;
	
	/**
	 * The realm of the user
	 */
	private $realm;
	
	/**
	 * The attribute map. It is an array
	 */
	
	private $attributemap = array();


    /**
     * OTP constructor.
     *
     * @param array $config The configuration of this authproc.
     * @param mixed $reserved
     *
     * @throws \SimpleSAML\Error\CriticalConfigurationError in case the configuration is wrong.
     */
    public function __construct(array $config, $reserved)
    {
        parent::__construct($config, $reserved);

        $cfg = \SimpleSAML_Configuration::loadFromArray($config, 'linotp2:OTP');
        $this->linotpserver= $cfg->getString('linotpserver');
        $this->linotpuidattribute = $cfg->getString('linotpuidattribute', 'uid');
        $this->sslverifyhost= $cfg->getBoolean('sslverifyhost', false);
        $this->sslverifypeer= $cfg->getBoolean('sslverifypeer', false);
        $this->realm = $cfg->getString('realm', '');
        $this->attributemap= $cfg->getArrayize('attributemap', array(
        		'username' => 'samlLoginName',
        		'surname' => 'surName',
        		'givenname' => 'givenName',
        		'email' => 'emailAddress',
        		'phone' => 'telePhone',
        		'mobile' => 'mobilePhone',
        ));
    }


    /**
     * Run the filter.
     *
     * @param array $state
     */
    public function process(&$state)
    {
        $session = \SimpleSAML_Session::getSessionFromRequest();
        $this->authid = $state['Source']['auth'];
        $key_id = $session->getData('linotp2:auth', $this->authid);
        $attrs = &$state['Attributes'];

        // check for previous auth
        if (!is_null($key_id) && in_array($key_id, $attrs[$this->linotpuidattribute])) {
            // we were already authenticated using a valid yubikey
            SimpleSAML\Logger::info('Reusing previous OTP authentication with data "'.$key_id.'".');
            return;
        }

        $state['linotp2:otp'] = array(
            'linotpserver' => $this->linotpserver,
            'linotpuidattribute' => $this->linotpuidattribute,
            'sslverifyhost' => $this->sslverifyhost,
            'sslverifypeer' => $this->sslverifypeer,
            'realm' => $this->realm,
            'attributemap' => $this->attributemap,
            'authID' => $this->authid,
            'self' => $this,
        );

        SimpleSAML\Logger::debug('Initiating LinOTP authentication.');

        $sid = \SimpleSAML_Auth_State::saveState($state, 'linotp2:otp:init');
        $url = SimpleSAML_Module::getModuleURL('linotp2/otp.php');
        SimpleSAML_Utilities::redirectTrustedURL($url, array('StateId' => $sid));
    }

    /**
     * Perform OTP authentication given the current state and a one time password entered by a user.
     *
     * @param array $state The state array in the "linotp2:otp:init" stage.
     * @param string $otp A one time password generated by a device registered with the LinOTP server.
     * @return boolean True if authentication succeeded and the key belongs to the user, false otherwise.
     *
     * @throws \InvalidArgumentException if the state array is not in a valid stage.
     */
    public static function authenticate(array &$state, $otp)
    {
        // validate the state array we're given
        if (!array_key_exists(\SimpleSAML_Auth_State::STAGE, $state) ||
            $state[\SimpleSAML_Auth_State::STAGE] !== 'linotp2:otp:init') {
            throw new \InvalidArgumentException("{linotp2:errors:invalid_state}");
        }
        $cfg = $state['linotp2:otp'];

        $otp = strtolower($otp);

        $username = $state['Attributes'][$cfg['linotpuidattribute']][0];
        assert('is_string($otp)');
        assert('is_string($username)');

        $ch = curl_init();

        $escPassword = urlencode($otp);
        $escUsername = urlencode($username);

        $url = $cfg['linotpserver'] . '/validate/samlcheck?user='.$escUsername
        .'&pass=' . $escPassword . '&realm=' . $cfg['realm'];

        //throw new Exception("url: ". $url);
        SimpleSAML\Logger::debug("LinOTP2 URL: " . $url);

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HEADER, TRUE);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        if ($cfg['sslverifyhost']) {
        	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 1);
        } else {
        	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        }
        if ($cfg['sslverifypeer']) {
        	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 1);
        } else {
        	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        }

        $response = curl_exec($ch);
        $header_size = curl_getinfo($ch,CURLINFO_HEADER_SIZE);
        $body = json_decode(substr( $response, $header_size ));

        $status=True;
        $value=True;

        try {
        	$status = $body->result->status;
        	$value = $body->result->value->auth;
        } catch (Exception $e) {
        	throw new SimpleSAML_Error_BadRequest("We were not able to read the response from the LinOTP server: " . $e);
        }

        if ( False==$status ) {
          /* We got a valid JSON respnse, but the STATUS is false */
          SimpleSAML\Logger::info('Valid JSON response, but some internal error occured in LinOTP server.');
          return false;
        }
        else {
        	/* The STATUS is true, so we need to check the value */
        	if ( False==$value ) {
            SimpleSAML\Logger::info('LinOTP reports invalid OTP for user "'.$username.'".');
            return false;
          }
          else {
            SimpleSAML\Logger::info('Successful authentication with LinOTP for user "'.$username.'".');
            return true;
        	}
        }
        // Fail safe at the end.
        return false;
    }


    /**
     * A logout handler that makes sure to remove the key from the session, so that the user is asked for the key again
     * in case of a re-authentication with this very same session.
     */
    public function logoutHandler()
    {
        $session = \SimpleSAML_Session::getSessionFromRequest();
        $keyid = $session->getData('linotp2:auth', $session->getAuthority());
        SimpleSAML\Logger::info('Removing valid LinOTP authentication with data "'.$keyid.'".');
        $session->deleteData('linotp2:auth', $session->getAuthority());
    }
}
