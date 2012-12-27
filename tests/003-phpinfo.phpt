--TEST--
Check if module exists (php info)
--FILE--
<?php
phpinfo();
?>
--EXPECTREGEX--
.*Lib OpenDKIM Version.*
