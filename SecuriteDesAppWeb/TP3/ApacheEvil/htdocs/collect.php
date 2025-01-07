<?php
// Autoriser les requêtes CORS
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

// Si la requête est une requête OPTIONS (pré-volée), terminer ici
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}
// Nom du fichier où les secrets seront enregistrés
$file = "secrets.txt";

// Vérifie si la méthode de requête est POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Récupère les données JSON envoyées
    $data = file_get_contents("php://input");
    $decodedData = json_decode($data, true);

    // Vérifie si le champ 'secret' est présent
    if (isset($decodedData['secret'])) {
        $secret = $decodedData['secret'];

        // Ajoute le secret au fichier avec un horodatage
        file_put_contents($file, "[" . date("Y-m-d H:i:s") . "] Secret: " . $secret . PHP_EOL, FILE_APPEND);

        // Réponse de confirmation
        echo json_encode(["status" => "success", "message" => "Secret enregistré"]);
    } else {
        // Erreur si 'secret' n'est pas présent
        echo json_encode(["status" => "error", "message" => "Aucun secret reçu"]);
    }
} else {
    // Erreur si la méthode n'est pas POST
    echo json_encode(["status" => "error", "message" => "Méthode non autorisée"]);
}
?>
