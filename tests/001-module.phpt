--TEST--
Check if module exists
--FILE--
<?php
if (extension_loaded('opendkim')) {
    echo 'OK';
}
?>
--EXPECT--
OK

