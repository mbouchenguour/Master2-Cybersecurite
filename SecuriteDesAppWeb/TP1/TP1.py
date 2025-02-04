import os
from flask import Flask, request, jsonify
import subprocess


app = Flask(__name__)

UPLOAD_FOLDER = "C:/Users/Momol/Documents/GitHub/Master2-Cybersecurite/SecuriteDesAppWeb/TP1/docs"

def lire_fichier(nom_du_fichier):
    file_path = os.path.join(UPLOAD_FOLDER, nom_du_fichier)
    try:
        with open(file_path, "r", encoding="utf-8") as fichier:
            contenu_fichier = fichier.read()
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
