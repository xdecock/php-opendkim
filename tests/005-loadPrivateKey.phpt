--TEST--
Try to instanciante DKIMSigner
--FILE--
<?php
if ($dkim = new OpenDKIMSign(file_get_contents(__DIR__.'/keys/private.1024.key'), 'example.com', 'selector')) {
    if ($dkim->loadPrivateKey()) {
        echo 'OK';
    }
    if (!$dkim->header('From: test@example.com')) {
      die('KO'.__LINE__.$dkim->getError());
    }
    if (!$dkim->eoh()) {
      die('KO'.__LINE__.$dkim->getError());
    }
    if (OpenDKIM::STAT_OK!=$dkim->eom()) {
      die('KO'.__LINE__.$dkim->getError());
    }
}
?>
--EXPECT--
OK
