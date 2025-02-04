// Fonction pour supprimer un cookie via JavaScript avec un path spécifié
function deleteCookie(name, path = "") {
    let cookieString = name + "=; expires=Thu, 01 Jan 1970 00:00:00 UTC;";
    if (path) {
        cookieString += " path=" + path + ";";
    }
    document.cookie = cookieString;
    console.log(`Cookie "${name}" supprimé avec path="${path || 'default'}".`);
}

// 🔹 Supprimer tous les cookies accessibles par JavaScript
deleteCookie("CookieService1", "/");          // Supprime sans path (utilise le path par défaut)
deleteCookie("CookieService2", "/");     // Supprime avec path=/ (si défini avec path=/)
deleteCookie("CookieService1_HttpOnly", "/"); // Supprime avec un path spécifique
deleteCookie("CookieService2_HttpOnly", "/");

// 🔹 Vérifier les cookies restants après suppression
console.log("Cookies accessibles après suppression :", document.cookie);
