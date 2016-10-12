<!DOCTYPE html>
<html>
<head>
<title>Vulnerable JSONP endpoint caller</title>
<?php

echo '<script src="http://victim.com/some/jsonp_data.php?callback='.$_GET["callback"].'"></script>'

?>
</head>


</html>
