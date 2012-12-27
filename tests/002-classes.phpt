--TEST--
Verify Classes Existence
--FILE--
<?php
if (class_exists('OpenDKIM')) {
    echo "OpenDKIM\n";
}
if (class_exists('OpenDKIMSign')) {
    echo "OpenDKIMSign\n";
}
if (class_exists('OpenDKIMVerify')) {
    echo "OpenDKIMVerify\n";
}
?>
--EXPECT--
OpenDKIM
OpenDKIMSign
OpenDKIMVerify

