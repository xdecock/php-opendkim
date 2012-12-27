--TEST--
Sign a message
--FILE--
<?php
if (!($dkim = new OpenDKIMSign(file_get_contents(__DIR__.'/keys/private.1024.key'), 'selector', 'example.com'))) {
    die('KO:'.__LINE__.':'.$dkim->getError());
}
if (!$dkim->loadPrivateKey()) {
    die('KO:'.__LINE__.':'.$dkim->getError());
}
if (!$dkim->header('From: test@example.com')) {
    die('KO:'.__LINE__.':'.$dkim->getError());
}
if (!$dkim->header('Sender: test3@example.com')) {
    die('KO:'.__LINE__.':'.$dkim->getError());
}
if (!$dkim->header('To: test2@example.com')) {
    die('KO:'.__LINE__.':'.$dkim->getError());
}
if (!$dkim->header('Subject: Test')) {
    die('KO:'.__LINE__.':'.$dkim->getError());
}
if (!$dkim->header('Date: Tue, 18 Dec 2012 22:10:56 +0100')) {
    die('KO:'.__LINE__.':'.$dkim->getError());
}
if (!$dkim->eoh()) {
    die('KO:'.__LINE__.':'.$dkim->getError());
}
if (!$dkim->body('Test'."\r\n")) {
    die('KO:'.__LINE__.':'.$dkim->getError());
}
if (!$dkim->body('Second Line'."\r\n")) {
    die('KO:'.__LINE__.':'.$dkim->getError());
}
if(!$dkim->setMargin(99)) {
    die ('KO:'.__LINE__.':'.$dkim->getError());
}
if (!$dkim->setSigner('signer@example.com')) {
    die ('KO:'.__LINE__.':'.$dkim->getError());
}
if (!$dkim->setPartial(false)) {
    die ('KO:'.__LINE__.':'.$dkim->getError());
}
if(!$dkim->eom()) {
    die ('KO:'.__LINE__.':'.$dkim->getError());
}
$header=$dkim->getSignatureHeader();
echo "OK\n";
echo "DKIM-Signature: ".$header;
?>
--EXPECTREGEX--
OK
DKIM-Signature: .*
