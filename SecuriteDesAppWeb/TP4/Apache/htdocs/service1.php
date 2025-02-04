<?php
setcookie("CookieService1", "1");

setcookie("CookieService1_HttpOnly", "1", [
    "httponly" => true  // Empêche JavaScript d’accéder et de supprimer ce cookie
]);

?>
<!DOCTYPE html>
<html>
<head>
    <title>Service 1</title>
</head>
<body>
    <h1>Service 1</h1>
    <p>Cookie défini : CookieService1=1</p>
</body>
</html>
