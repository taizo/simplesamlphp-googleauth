<?php

$config['googleauth'] = array(
        'googleauth:OpenIDConsumer',
        'uri.endpoint_prefix' => 'https://www.google.com/accounts/o8', // Optional: default:null(regard as https://www.google.com/accounts/o8)
        'request.force_login' => false, // Optional: default:false
        'request.ext_ax_type' => false, // Optional: default:false
);

$config_file = "/usr/share/php/simplesamlphp/extra/googleauth.conf";
if (file_exists($config_file)) {
        foreach (file($config_file) as $_line) {
                $params = explode("=",$_line,2);
                $value = trim($params[1]);
                $value = preg_replace("/^['\"]/","",$value);
                $value = preg_replace("/['\"]$/","",$value);
                $config['googleauth'][$params[0]] = $value;
        }
}
?>
