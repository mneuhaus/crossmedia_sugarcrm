<?php
/***************************************************************
*  Copyright notice
*
*  (c) 2004 Norman Seibert (seibert@entios.de)
*  All rights reserved
*
*  This script is part of the TYPO3 project. The TYPO3 project is
*  free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2 of the License, or
*  (at your option) any later version.
*
*  The GNU General Public License can be found at
*  http://www.gnu.org/copyleft/gpl.html.
*
*  This script is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  This copyright notice MUST APPEAR in all copies of the script!
***************************************************************/
/**
 * Service 'LDAP-Authentication' for the 'cc_svauthdemo' extension.
 *
 * @author	Norman Seibert <seibert@entios.de>
 */


class Tx_CrossmediaSugarcrm_Service_Authentication extends tx_sv_authbase {
	protected $prefixId = 'tx_euldap_sv1';
	protected $scriptRelPath = 'Classes/Service/Authentication.php';
	protected $extKey = 'crossmedia_sugarcrm';
	protected $conf;
	protected $logLevel = 2;

	public function initAuth($subType, array $loginData, array $authenticationInformation, t3lib_userAuth &$parentObject) {
		$this->loginData = $loginData;
		$this->authInfo = $authenticationInformation;
		$this->password = $this->loginData['uident_text'];
		$this->username = $this->loginData['uname'];

		$this->pObj = $parentObject;
	}

	public function getUser() {
		$OK = FALSE;
		$user = NULL;

		if ($this->logLevel > 0) {
			t3lib_div::devLog('getUser() called', 'eu_ldap', 0);
		}
		if ($this->loginData['status'] == 'login') {
			if ($this->logLevel > 1) {
				t3lib_div::devLog('no session found', 'eu_ldap', 0);
			}
			if ($this->username) {
				if ($this->pObj->security_level == 'rsa') {
					if (!t3lib_extMgm::isLoaded('rsaauth')) {
						if ($this->logLevel) {
							t3lib_div::devLog('security_level is "rsa" but "rsaauth" is not loaded', 'eu_ldap', 3);
						}
						return FALSE;
					}
					require_once(t3lib_extMgm::extPath('rsaauth') . 'sv1/backends/class.tx_rsaauth_backendfactory.php');
					require_once(t3lib_extMgm::extPath('rsaauth') . 'sv1/storage/class.tx_rsaauth_storagefactory.php');
					$backend = tx_rsaauth_backendfactory::getBackend();
					$storage = tx_rsaauth_storagefactory::getStorage();

					$this->password = $this->loginData['uident'];
					$key = $storage->get();

					if ($key != NULL && substr($this->password, 0, 4) == 'rsa:') {
						$decryptedPassword = $backend->decrypt($key, substr($this->password, 4));
						$this->password = $decryptedPassword;
					} elseif ($this->logLevel) {
						t3lib_div::devLog('unable to RSA-decrypt password', 'eu_ldap', 3);
					}
				}

				if ($this->logLevel > 0) {
					t3lib_div::devLog('user name: ' . $this->username, 'eu_ldap', 0);
				}
				if ($this->logLevel == 2) {
					t3lib_div::devLog('user name / password: ' . $this->username . ' / ' . $this->password, 'eu_ldap', 0);
				}

				if ($this->authInfo['loginType'] == 'BE') {
					$whereclause = 'deleted = 0 AND hidden = 0';
				} else {
					$whereclause = 'deleted = 0 AND hidden = 0 AND pid IN (' . $this->authInfo['db_user']['checkPidList'] . ')';
				}

				$dbres = $GLOBALS['TYPO3_DB']->exec_SELECTquery(
					'uid, title',
					$this->authInfo['db_groups']['table'],
					$whereclause
				);

				/*

					# SugarCRM Integration

					Check if user exists, else import from sugar.

					For now every user gets logged in as toni

				 */

				$sql = $GLOBALS['TYPO3_DB']->exec_SELECTquery(
					'*',
					$this->authInfo['db_user']['table'],
					"username = 'toni'" . $this->authInfo['db_user']['check_pid_clause'] . $this->authInfo['db_user']['enable_clause']
				);
				$user = $GLOBALS['TYPO3_DB']->sql_fetch_assoc($sql);
				$user['authenticated'] = TRUE;

			}
		}

		return $user;
	}

	/**
	 * authenticate a user
	 *
	 * @param	array		Data of user.
	 * @return	boolean
	 */
	public function authUser(&$user) {
		$OK = 100;

		if ($this->username) {
			$OK = 0;

			$OK = $user['authenticated'];

			if (!$OK) {
					// Failed login attempt (wrong password) - write that to the log!
				if ($this->writeAttemptLog) {
					$this->writelog(255, 3, 3, 1,
						"Login-attempt from %s (%s), username '%s', password not accepted!",
						array($this->info['REMOTE_ADDR'], $this->info['REMOTE_HOST'], $this->username));
				}
				if ($this->logLevel == 1) {
					t3lib_div::devLog('Password not accepted: ' . $this->password, 'eu_ldap', 2);
				}
			}

			$OK = $OK ? 200 : ($this->conf['onlyLDAP'] ? 0 : 100);
		}

		if ($OK && $user['lockToDomain'] && $user['lockToDomain'] != $this->authInfo['HTTP_HOST']) {
				// Lock domain didn't match, so error:
			if ($this->writeAttemptLog) {
				$this->writelog(255, 3, 3, 1,
					"Login-attempt from %s (%s), username '%s', locked domain '%s' did not match '%s'!",
					Array($this->authInfo['REMOTE_ADDR'], $this->authInfo['REMOTE_HOST'], $user[$this->authInfo['db_user']['username_column']], $user['lockToDomain'], $this->authInfo['HTTP_HOST']));
				t3lib_div::sysLog(
					sprintf( "Login-attempt from %s (%s), username '%s', locked domain '%s' did not match '%s'!", $this->authInfo['REMOTE_ADDR'], $this->authInfo['REMOTE_HOST'], $user[$this->authInfo['db_user']['username_column']], $user['lockToDomain'], $this->authInfo['HTTP_HOST'] ),
					'Core',
					0
				);
			}
			$OK = FALSE;
		}

		return $OK;
	}

}



if (defined('TYPO3_MODE') && $TYPO3_CONF_VARS[TYPO3_MODE]['XCLASS']['ext/crossmedia_sugarcrm/Classes/Service/Authentication.php']) {
	include_once($TYPO3_CONF_VARS[TYPO3_MODE]['XCLASS']['ext/crossmedia_sugarcrm/Classes/Service/Authentication.php']);
}

?>