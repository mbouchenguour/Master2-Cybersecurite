from flask import Flask, request, jsonify, render_template
from smartcard.System import readers
import rsa
import base64
import re
from utils import verify_transaction_blocks, handle_multi_apdu, get_rsa_key, select_applet, verify_pin 


app = Flask(__name__)

# Générer une paire de clés RSA de 512 bits
SERVER_PUBLIC_KEY, SERVER_PRIVATE_KEY = rsa.newkeys(512)

# Base de données simulée
database = {
    "cards": []  # Stocke les clés publiques des cartes
}
stolen_cards = set()  # Stocke les clés publiques des cartes volées
transactions = []  # Stocke les transactions reçues


INS_DECRYPT_LOG = 0x0A

def decrypt_logs(connection, transactions):
    """
    Envoie une transaction  à la carte pour déchiffrement.

    :param connection: Connexion à la carte.
    :param transaction_b64: Transactions.
    :return: Données déchiffrées (bytes).
    """

    decrypted = handle_multi_apdu(connection, INS_DECRYPT_LOG, data=transactions)

    # Conversion en chaîne
    result = ''.join(chr(byte) for byte in decrypted)

    return result
    

@app.route('/cards', methods=['GET'])
def get_cards():
    """
    Retourne toutes les clés publiques enregistrées dans la base de données.
    """
    if not database["cards"]:
        return jsonify({"message": "Aucune carte enregistrée"}), 200

    return jsonify({"cards": database["cards"]}), 200


@app.route('/register', methods=['POST'])
def register_card():
    """Enregistre la clé publique de la carte."""
    data = request.json
    public_key = data.get("public_key")

    if not public_key:
        return jsonify({"error": "Clé publique manquante"}), 400

    if public_key in stolen_cards:
        return jsonify({"error": "Carte signalée comme volée"}), 403

    # Ajouter la clé publique de la carte à la base de données
    if public_key not in database["cards"]:
        database["cards"].append(public_key)
        return jsonify({"message": "Clé publique enregistrée avec succès"}), 200
    else:
        return jsonify({"message": "Clé publique déjà enregistrée"}), 200


@app.route('/public_key', methods=['GET'])
def get_server_public_key():
    """Retourne la clé publique du serveur."""
    return jsonify({"public_key": SERVER_PUBLIC_KEY.save_pkcs1().decode('utf-8')}), 200


@app.route('/mark_stolen', methods=['POST'])
def mark_card_as_stolen():
    """
    Marque une carte comme volée.
    """
    data = request.json
    public_key = data.get("public_key")

    if not public_key:
        return jsonify({"error": "Clé publique manquante"}), 400

    if public_key not in database["cards"]:
        return jsonify({"error": "Carte introuvable"}), 404

    stolen_cards.add(public_key)
    return jsonify({"message": "Carte marquée comme volée"}), 200


@app.route('/is_stolen', methods=['POST'])
def is_card_stolen():
    """
    Vérifie si une carte est marquée comme volée.
    """
    data = request.json
    public_key = data.get("public_key")

    if not public_key:
        return jsonify({"error": "Clé publique manquante"}), 400

    if public_key in stolen_cards:
        return jsonify({"message": "Carte volée"}), 200
    else:
        return jsonify({"message": "Carte valide"}), 200
    

@app.route('/time', methods=['GET'])
def get_time():
    """
    Retourne la date et l'heure actuelle signée par le serveur.
    """
    from datetime import datetime

    # Obtenir la date et l'heure actuelles
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Signer avec la clé privée
    signature = rsa.sign(now.encode('utf-8'), SERVER_PRIVATE_KEY, 'SHA-1')
    
    signature_base64 = base64.b64encode(signature).decode('utf-8')

    return jsonify({"time": now, "signature": signature_base64}), 200



@app.route('/transaction', methods=['POST'])
def transaction():
    """
    Reçoit une transaction (encodée en Base64) et une clé publique.
    Enregistre uniquement les données sans effectuer d'opération.
    """
    # Récupérer les données envoyées
    data = request.json
    transaction_base64 = data.get("transaction")
    public_key_pem = data.get("public_key")

    if not transaction_base64 or not public_key_pem:
        return jsonify({"error": "Données manquantes (transaction ou public_key)"}), 400

    #Vérifie que la carte existe dans la bdd
    if public_key_pem not in database["cards"]:
        return jsonify({"error": "Carte introuvable"}), 404
    
    # Vérifier que la carte n’est pas marquée comme volée
    if public_key_pem in stolen_cards:
        return jsonify({"error": "Transaction refusée, carte signalée comme volée"}), 403
    
    verif = verify_transaction_blocks(base64.b64decode(transaction_base64), public_key_pem)
    if(verif):
        # Enregistrer la transaction sans aucune autre opération
        transactions.append({
            "transaction": transaction_base64,
            "public_key": public_key_pem,
        })
        return jsonify({"message": "Transaction reçue et enregistrée avec succès"}), 200
    else:
        return jsonify({"message": "Échec de la vérification de la transaction"}), 400

@app.route('/transactions', methods=['GET'])
def get_transactions():
    """
    Retourne toutes les transactions enregistrées.
    """
    if not transactions:
        return jsonify({"message": "Aucune transaction enregistrée"}), 200

    return jsonify({"transactions": transactions}), 200

@app.route('/connect', methods=['GET', 'POST'])
def connect_card():
    """
    Page principale pour se connecter à la carte, valider le PIN, et afficher les transactions.
    """
    try:
        # Vérifier les lecteurs disponibles
        available_readers = readers()
        if not available_readers:
            return render_template('connect.html', message="Aucune carte détectée. Connectez une carte.")

        # Se connecter au premier lecteur disponible
        reader = available_readers[0]
        connection = reader.createConnection()
        connection.connect()
        select_applet(connection)
        # Récupérer la clé publique de la carte
        public_key_pem = get_rsa_key(connection)

        # Vérifier si la carte est signalée comme volée
        if public_key_pem in stolen_cards:
            return render_template('connect.html', message="Carte volée détectée. Connexion refusée.")
        
        if public_key_pem not in database["cards"]:
            return render_template('connect.html', message="Carte inconnue.")
        
        # Si POST : PIN soumis pour validation
        if request.method == 'POST':
            pin = request.form.get('pin', '')
            if not pin:
                return render_template('connect.html', message="Veuillez entrer un PIN.", public_key=public_key_pem)

            # Valider le PIN
            try:
                verify_pin(connection, pin)
                # Récupérer toutes les transactions associées à la clé publique
                filtered_transactions = [
                    transaction["transaction"]
                    for transaction in transactions
                    if transaction["public_key"] == public_key_pem
                ]

                if not filtered_transactions:
                    return render_template('connect.html', message="Aucune transaction à envoyer.", public_key=public_key_pem)

                decrypted_transactions = []

                for encoded_tx in filtered_transactions:
                    # Décoder chaque transaction (Base64 -> bytes)
                    decoded_tx = base64.b64decode(encoded_tx)

                    # Envoyer à la carte pour décryptage
                    decrypted_tx = decrypt_logs(connection, decoded_tx)

                    # Ajouter le résultat à la liste
                    decrypted_transactions.append(decrypted_tx)

                # Concaténer toutes les transactions décryptées
                concatenated_transactions = ''.join(decrypted_transactions)

                # Ajouter un saut de ligne avant chaque date au format YYYY-MM-DD HH:MM:SS
                formatted_transactions = re.sub(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", r"\n\1", concatenated_transactions)

                # Supprimer le saut de ligne initial si présent
                formatted_transactions = formatted_transactions.lstrip()

                return render_template(
                                    'connect.html',
                                    message="Transactions décryptées avec succès !",
                                    public_key=public_key_pem,
                                    transactions=formatted_transactions
                                )
            
            except Exception as e:
                return render_template('connect.html', message=f"Échec de la vérification du PIN : {str(e)}", public_key=public_key_pem)

        # Sinon, afficher le formulaire pour entrer le PIN
        return render_template('connect.html', public_key=public_key_pem)
    
    except Exception as e:
        return render_template('connect.html', message=f"Erreur : {str(e)}")

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
