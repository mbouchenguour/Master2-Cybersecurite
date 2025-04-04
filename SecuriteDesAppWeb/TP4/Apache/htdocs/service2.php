<?php
setcookie("CookieService2", "2");

setcookie("CookieService2_HttpOnly", "2", [
    "httponly" => true  // Empêche JavaScript d’accéder et de supprimer ce cookie
]);

setcookie("CookieService2_Secure", "2", [
    "secure" => True
]);

setcookie("CookieService2_Lax", "2", [
    "samesite" => "Lax"
]);

setcookie("CookieService2_Strict", "CookieStrict", [
    'samesite' => 'Strict',
]);

setcookie("CookieService2_None", "2", [
    "samesite" => "None",
    "secure" => true // Nécessaire pour `SameSite=None`
]);





if ($_SERVER["REQUEST_METHOD"] === "POST") {
    setcookie("CookieService1", "", time() - 3600);
    setcookie("CookieService1_HttpOnly", "", time() - 3600);
    //setcookie("CookieService1", "", time() - 3600, "/service1");
    //setcookie("CookieService1_HttpOnly", "", time() - 3600, "/service1");
}

?>
<!DOCTYPE html>
<html>
<head>
    <title>Service 2</title>
</head>
<body>
    <h1>Service 2</h1>
    <p>Cookie défini : CookieService2=2</p>
    <form method="POST">
        <button type="submit">Supprimer les cookies de Service 1</button>
    </form>
</body>
</html>
