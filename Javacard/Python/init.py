from smartcard.System import readers
import requests
from utils import send_apdu, CLA_PROJET, SW_COMMAND_SUCCESS, get_rsa_key, select_applet, verify_pin 

INS_SET_PIN = 0x02
INS_SET_SERVER_KEY = 0x05



SERVER_URL = "http://127.0.0.1"  # Adresse du serveur de vérification



def set_pin(connection, pin):
    """Envoie le PIN pour initialiser la carte."""
    if len(pin) != 4 or not pin.isdigit():
        raise ValueError("Le PIN doit contenir exactement 4 chiffres.")
    pin_data = [ord(c) for c in pin]
    apdu_set_pin = [CLA_PROJET, INS_SET_PIN, 0x00, 0x00, len(pin_data)] + pin_data
    _, sw1, sw2 = send_apdu(connection, apdu_set_pin)
    if (sw1 << 8 | sw2) != SW_COMMAND_SUCCESS:
        raise RuntimeError(f"Échec de l'initialisation du PIN. SW1: {sw1:02X}, SW2: {sw2:02X}")


def set_server_key(connection, server_public_key_pem):
    """
    Déploie la clé publique du serveur sur la carte.
    
    La clé publique est au format PEM et est convertie en exposant + module avant l'envoi.
    """
    import rsa

    # Charger la clé publique depuis le format PEM
    public_key = rsa.PublicKey.load_pkcs1(server_public_key_pem.encode('utf-8'), format='PEM')

    # Extraire l'exposant et le module
    exponent = public_key.e.to_bytes((public_key.e.bit_length() + 7) // 8, 'big')
    modulus = public_key.n.to_bytes((public_key.n.bit_length() + 7) // 8, 'big')

    # Construire les données APDU
    server_key_data = (
        [len(exponent)] + list(exponent) +  # Longueur de l'exposant + valeur de l'exposant
        [len(modulus)] + list(modulus)     # Longueur du module + valeur du module
    )
    apdu_set_server_key = [CLA_PROJET, INS_SET_SERVER_KEY, 0x00, 0x00, len(server_key_data)] + server_key_data

    # Debug : Afficher les données APDU pour vérification
    #print(f"APDU construite : {apdu_set_server_key}")

    # Envoyer la commande APDU à la carte
    _, sw1, sw2 = send_apdu(connection, apdu_set_server_key)

    # Vérifier le statut de la réponse
    if (sw1 << 8 | sw2) != SW_COMMAND_SUCCESS:
        raise RuntimeError(f"Échec du déploiement de la clé publique du serveur. SW1: {sw1:02X}, SW2: {sw2:02X}")

    print("Clé publique du serveur déployée avec succès sur la carte.")

def is_server_online():
    """Vérifie si le serveur est accessible en effectuant une requête GET."""
    try:
        response = requests.get(SERVER_URL, timeout=5)
        return response.status_code < 500  # Considère les codes <500 comme une disponibilité du serveur
    except requests.RequestException:
        return False


def main():

    # Vérification si le serveur est lancé
    if not is_server_online():
        print("Le serveur est inaccessible. Veuillez vérifier qu'il est lancé.")
        return
    
    # Initialisation du lecteur et connexion à la carte
    available_readers = readers()
    if not available_readers:
        print("Aucun lecteur de carte trouvé.")
        return

    reader = available_readers[0]
    connection = reader.createConnection()
    try:
        connection.connect()
        select_applet(connection)

        # Étape 1 : Initialiser le PIN
        pin = input("Entrez un code PIN (4 chiffres pour initialisation) : ")
        set_pin(connection, pin)
        print("PIN initialisé avec succès.")

        # Étape 2 : Saisir le PIN
        pin = input("Entrez un code PIN pour vérification : ")
        verify_pin(connection, pin)

        # Étape 3 : Récupère la clé RSA public de la carte
        public_key = get_rsa_key(connection)
        print(f"Clé publique générée sur la carte : {public_key}")

        # Étape 4 : Enregistrer la clé publique auprès du serveur
        response = requests.post(f"{SERVER_URL}/register", json={"public_key": public_key})
        response.raise_for_status()
        print("Clé publique enregistrée sur le serveur.")

        # Étape 5 : Récupérer la clé publique du serveur
        response = requests.get(f"{SERVER_URL}/public_key")
        response.raise_for_status()
        server_public_key = response.json()["public_key"]
        print(f"Clé publique du serveur récupérée : {server_public_key}")

        # Étape 6 : Déployer la clé publique du serveur sur la carte
        set_server_key(connection, server_public_key)
        print("Clé publique du serveur déployée sur la carte avec succès.")

    except Exception as e:
        print(f"Erreur : {e}")


if __name__ == "__main__":
    main()
