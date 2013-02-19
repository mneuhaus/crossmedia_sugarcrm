<?php
if (!defined('TYPO3_MODE')) {
	die ('Access denied.');
}

// Tx_Extbase_Utility_Extension::configurePlugin(
// 	$_EXTKEY,
// 	'Sugarcrm',
// 	array(
// 		'Standard' => 'index, new, create',

// 	),
// 	// non-cacheable actions
// 	array(

// 	)
// );

if ($TYPO3_CONF_VARS['FE']['loginSecurityLevel'] != 'rsa') {
	$TYPO3_CONF_VARS['FE']['loginSecurityLevel'] = 'normal';
}

// register Service with highest priority
t3lib_extMgm::addService($_EXTKEY, 'auth', 'Tx_CrossmediaSugarcrm_Service_Authentication',
	array(
		'title' => 'SugarCRM-Authentication',
		'description' => 'Authentication service for SugarCRM.',
		'subtype' => 'getUserFE,authUserFE',
		'available' => 1,
		'priority' => 100,
		'quality' => 50,
		'os' => '',
		'exec' => '',
		'classFile' => t3lib_extMgm::extPath($_EXTKEY) . 'Classes/Service/Authentication.php',
		'className' => 'Tx_CrossmediaSugarcrm_Service_Authentication',
	)
);

?>