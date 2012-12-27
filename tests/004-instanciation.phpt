--TEST--
Try to instanciante DKIMSigner
--FILE--
<?php
if ($dkim = new OpenDKIMSign(file_get_contents(__DIR__.'/keys/private.1024.key'), 'example.com', 'selector')) {
    echo 'OK';
}
?>
--EXPECT--
OK
