<?php

/*
 * Disable strict error reporting, since the OpenID library
 * used is PHP4-compatible, and not PHP5 strict-standards compatible.
 */
SimpleSAML_Utilities::maskErrors(E_STRICT);

/* Add the OpenID library search path. */
set_include_path(get_include_path() . PATH_SEPARATOR . dirname(dirname(dirname(dirname(dirname(dirname(__FILE__)))))) . '/lib');

require_once('Auth/OpenID/AX.php');
require_once('Auth/OpenID/SReg.php');
require_once('Auth/OpenID/Server.php');
require_once('Auth/OpenID/ServerRequest.php');


/**
 * Authentication module which acts as an OpenID Consumer for Google Apps OpenID
 *
 * @author Taizo ITO <taizoster@gmail.com>
 * @package simpleSAMLphp
 * @version $Id$
 */
class sspmod_googleauth_Auth_Source_OpenIDConsumer extends SimpleSAML_Auth_Source {

	/**
	 * Static openid target to use.
	 *
	 * @var string|NULL
	 */
	private $target;

	/**
	 * Static openid AX attributes informations.
	 *
	 * @var string|NULL
	 */
	private $axAttrInfo;

	/**
	 * List of optional attributes.
	 */
	private $endpoint_prefix;
	private $account_domain;
	private $force_login;

	/**
	 * Constructor for this authentication source.
	 *
	 * @param array $info  Information about this authentication source.
	 * @param array $config  Configuration.
	 */
	public function __construct($info, $config) {

		/* Call the parent constructor first, as required by the interface. */
		parent::__construct($info, $config);

		$cfgParse = SimpleSAML_Configuration::loadFromArray($config,
			'Authentication source ' . var_export($this->authId, TRUE));

		$this->axAttrInfo = array('http://axschema.org/namePerson/first' => 'firstname',
			 		  'http://axschema.org/namePerson/last'  => 'lastname',
					  'http://axschema.org/contact/email'    => 'email');

		$this->requestExtArgs1 = array('openid.ns.ax'                    => 'http://openid.net/srv/ax/1.0',
			 		       'openid.ax.mode'                  => 'fetch_request',
			 		       'openid.ax.type.namePerson_first' => 'http://axschema.org/namePerson/first',
			 		       'openid.ax.type.namePerson_last'  => 'http://axschema.org/namePerson/last',
			 		       'openid.ax.type.contact_email'    => 'http://axschema.org/contact/email',
			 		       'openid.ax.required'              => 'namePerson_first,namePerson_last,contact_email',
			 		       'openid.ns.pape'                  => 'http://specs.openid.net/extensions/pape/1.0');
        
		$this->requestExtArgs2 = array('openid.pape.max_auth_age'        => '0',
			 		       'openid.ns.ui'                    => 'http://specs.openid.net/extensions/ui/1.0');

		$this->requestExtArgs3 = array('openid.ui.mode'                  => 'popup',
			 		       'openid.identity'                 => 'http://specs.openid.net/auth/2.0/identifier_select',
			 		       'openid.claimed_id'               => 'http://specs.openid.net/auth/2.0/identifier_select');

		$this->endpoint_prefix = $cfgParse->getString('option.endpoint_prefix', "https://www.google.com/accounts/o8");
		$this->account_domain  = $cfgParse->getString('option.account_domain',  null);
		$this->force_login     = $cfgParse->getBoolean('option.force_login',    false);

		if ($this->account_domain !== null) {
			$this->target = "%s/site-xrds?&hd=%s" % ($this->endpoint_prefix,$this->account_domain,);
		} else {
			$this->target = "%s/id" % ($this->endpoint_prefix,);
		}
	}


	/**
	 * Initiate authentication. Redirecting the user to the consumer endpoint 
	 * with a state Auth ID.
	 *
	 * @param array &$state  Information about the current authentication.
	 */
	public function authenticate(&$state) {
		assert('is_array($state)');

		$state['googleauth:AuthId'] = $this->authId;

		if ($this->target !== null) {
			$this->doAuth($state, $this->target);
		}

		$id = SimpleSAML_Auth_State::saveState($state, 'googleauth:state');

		$url = SimpleSAML_Module::getModuleURL('googleauth/consumer.php');
		SimpleSAML_Utilities::redirect($url, array('AuthState' => $id));
	}


	/**
	 * Retrieve the Auth_OpenID_Consumer instance.
	 *
	 * @param array &$state  The state array we are currently working with.
	 * @return Auth_OpenID_Consumer  The Auth_OpenID_Consumer instance.
	 */
	private function getConsumer(array &$state) {
		$store = new sspmod_googleauth_StateStore($state);
		$session = new sspmod_googleauth_SessionStore();
		return new Auth_OpenID_Consumer($store, $session);
	}


	/**
	 * Retrieve the URL we should return to after successful authentication.
	 *
	 * @return string  The URL we should return to after successful authentication.
	 */
	private function getReturnTo($stateId) {
		assert('is_string($stateId)');

		return SimpleSAML_Module::getModuleURL('googleauth/consumer.php', array(
			'returned' => 1,
			'AuthState' => $stateId,
		));
	}


	/**
	 * Retrieve the trust root for this openid site.
	 *
	 * @return string  The trust root.
	 */
	private function getTrustRoot() {
		return SimpleSAML_Utilities::selfURLhost();
	}


	/**
	 * Send an authentication request to the OpenID provider.
	 *
	 * @param array &$state  The state array.
	 * @param string $openid  The OpenID we should try to authenticate with.
	 */
	public function doAuth(array &$state, $openid="") {
		assert('is_string($openid)');

                if($openid == "") {
			$openid = $this->target;
                }

		$stateId = SimpleSAML_Auth_State::saveState($state, 'googleauth:state');

		$consumer = $this->getConsumer($state);

		// Begin the OpenID authentication process.
		$auth_request = $consumer->begin($openid);

		// No auth request means we can't begin OpenID.
		if (!$auth_request) {
			throw new Exception("Authentication error; not a valid OpenID.");
		}

		foreach ($this->requestExtArgs1 as $key => $value) {
			$auth_request->addExtensionArg(Auth_OpenID_BARE_NS, $key, $value);
		}

		if ($this->force_login !== false) {
			foreach ($this->requestExtArgs2 as $key => $value) {
				$auth_request->addExtensionArg(Auth_OpenID_BARE_NS, $key, $value);
			}
		}
 
		foreach ($this->requestExtArgs3 as $key => $value) {
			$auth_request->addExtensionArg(Auth_OpenID_BARE_NS, $key, $value);
		}

		// Redirect the user to the OpenID server for authentication.
		// Store the token for this authentication so we can verify the
		// response.

		// For OpenID 1, send a redirect.  For OpenID 2, use a Javascript
		// form to send a POST request to the server.
		if ($auth_request->shouldSendRedirect()) {
			$redirect_url = $auth_request->redirectURL($this->getTrustRoot(), $this->getReturnTo($stateId));

			// If the redirect URL can't be built, display an error message.
			if (Auth_OpenID::isFailure($redirect_url)) {
				throw new Exception("Could not redirect to server: " . $redirect_url->message);
			}

			SimpleSAML_Utilities::redirect($redirect_url);
		} else {
			// Generate form markup and render it.
			$form_id = 'openid_message';
			$form_html = $auth_request->formMarkup($this->getTrustRoot(), $this->getReturnTo($stateId), FALSE, array('id' => $form_id));

			// Display an error if the form markup couldn't be generated; otherwise, render the HTML.
			if (Auth_OpenID::isFailure($form_html)) {
				throw new Exception("Could not redirect to server: " . $form_html->message);
			} else {
				echo '<html><head><title>OpenID transaction in progress</title></head>
					<body onload=\'document.getElementById("' . $form_id . '").submit()\'>' .
					$form_html . '</body></html>';
				exit;
			}
		}
	}


	/**
	 * Process an authentication response.
	 *
	 * @param array &$state  The state array.
	 */
	public function postAuth(array &$state) {

		$consumer = $this->getConsumer($state);

		$return_to = SimpleSAML_Utilities::selfURL();

		// Complete the authentication process using the server's
		// response.
		$response = $consumer->complete($return_to);

		// Check the response status.
		if ($response->status == Auth_OpenID_CANCEL) {
			// This means the authentication was cancelled.
			throw new Exception('Verification cancelled.');
		} else if ($response->status == Auth_OpenID_FAILURE) {
			// Authentication failed; display the error message.
			throw new Exception("OpenID authentication failed: " . $response->message);
		} else if ($response->status != Auth_OpenID_SUCCESS) {
			throw new Exceptioon('General error. Try again.');
		}

		// This means the authentication succeeded; extract the
		// identity URL and Simple Registration data (if it was
		// returned).
		$openid = $response->identity_url;

		$attributes = array('openid' => array($openid));
		$attributes['openid.server_url'] = array($response->endpoint->server_url);

		if ($response->endpoint->canonicalID) {
			$attributes['openid.canonicalID'] = array($response->endpoint->canonicalID);
		}

		if ($response->endpoint->local_id) {
				$attributes['openid.local_id'] = array($response->endpoint->local_id);
		}

		// Get AX response information
		$ax = new Auth_OpenID_AX_FetchResponse();
		$ax_resp = $ax->fromSuccessResponse($response);

		if (($ax_resp instanceof Auth_OpenID_AX_FetchResponse) && (!empty($ax_resp->data))) {
			$axresponse = $ax_resp->data;

			$attributes['openid.axkeys'] = array_keys($axresponse);
			foreach ($axresponse AS $axkey => $axvalue) {
				if (preg_match("/^\w+:/",$axkey)) {
					$attributes[$axkey] = (is_array($axvalue)) ? $axvalue : array($axvalue);
				} else {
					SimpleSAML_Logger::warning('Invalid attribute name in AX response: ' . var_export($axkey, TRUE));
				}
			}
		}

		foreach ($this->axAttrInfo as $key => $value) {
			if (isset($attributes[$key])) {
				$attributes[$value] = $attributes[$key];
				unset($attributes[$key]);
			}
		}

		SimpleSAML_Logger::debug('OpenID Returned Attributes: '. implode(", ",array_keys($attributes)));

		$state['Attributes'] = $attributes;
		SimpleSAML_Auth_Source::completeAuth($state);
	}

}
