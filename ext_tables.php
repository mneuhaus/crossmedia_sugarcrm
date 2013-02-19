<?php
if (!defined('TYPO3_MODE')) {
	die ('Access denied.');
}

Tx_Extbase_Utility_Extension::registerPlugin(
	$_EXTKEY,
	'Sugarcrm',
	'SugarCRM'
);

t3lib_extMgm::addStaticFile($_EXTKEY, 'Configuration/TypoScript', 'SugarCRM Integration');

?>