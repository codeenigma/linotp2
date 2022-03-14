<?php

/**
 * This page asks the user to authenticate using an OTP from a device
 * registered with your LinOTP server.
 * 
 * Largely based on code by Jaime Pérez Crespo,
 * UNINETT AS <jaime.perez@uninett.no>.
 *
 * @author Greg Harvey, Code Enigma <greg.harvey@codeenigma.com>.
 * @package SimpleSAMLphp\Module\linotp2
 */

if (!array_key_exists('StateId', $_REQUEST)) {
    throw new \SimpleSAML\Error\BadRequest('Missing AuthState parameter.');
}
$authStateId = $_REQUEST['StateId'];
$state = \SimpleSAML\Auth\State::loadState($authStateId, 'linotp2:otp:init');

$error = false;
if (array_key_exists('otp', $_POST)) { // we were given an OTP
    try {
    	if (\SimpleSAML\Module\linotp2\Auth\Process\OTP::authenticate($state, $_POST['otp'])) {
            \SimpleSAML\Auth\State::saveState($state, 'linotp2:otp:init');
            \SimpleSAML\Auth\ProcessingChain::resumeProcessing($state);
        } else {
            $error = '{linotp2:errors:invalid_otp}';
        }
    } catch (\InvalidArgumentException $e) {
        $error = $e->getMessage();
    }
}

$cfg = \SimpleSAML\Configuration::getInstance();
$tpl = new \SimpleSAML\XHTML\Template($cfg, 'linotp2:otp.php');
$tpl->data['params'] = array('StateId' => $authStateId);
$tpl->data['error'] = ($error) ? $tpl->t($error) : false;
$tpl->show();
