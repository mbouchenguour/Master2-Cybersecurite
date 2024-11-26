from flask import Flask, request, jsonify
from pathlib import Path

app = Flask(__name__)

def lire_fichier(nom_du_fichier):
    repertoire_principal = Path("C:/Users/Momol/Documents/Master2-Cybersecurite/SecuriteDesAppWeb/TP1/docs")
    chemin_complet = repertoire_principal / nom_du_fichier
    
    try:
        contenu_fichier = chemin_complet.read_text()
        return contenu_fichier
    except FileNotFoundError:
        return "Le fichier n'existe pas."
    except Exception as erreur:
        return f"Une erreur s'est produite : {erreur}"

@app.route("/lire_fichier", methods=["GET"])
def lire_fichier_api():
    nom_du_fichier = request.args.get("nom")
    if not nom_du_fichier:
        return jsonify({"erreur": "Paramètre 'nom' manquant."}), 400
    
    contenu = lire_fichier(nom_du_fichier)
    return jsonify({"contenu": contenu})

if __name__ == "__main__":
    app.run(debug=True)
