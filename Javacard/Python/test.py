from smartcard.System import readers
from smartcard.util import toHexString
import rsa, os, base64, requests
from utils import verify_transaction_blocks, CLA_PROJET, INS_GET_SERVER_IP, send_apdu, send_apdu_with_length_handling, SW_COMMAND_SUCCESS, handle_multi_apdu, INS_PAY, get_rsa_key, select_applet, verify_pin 

# Constantes nécessaires
SW_WRONG_LENGTH = 0x6C
INS_DECRYPT_LOG = 0x0A
INS_HELLO = 0x01
INS_SIMPLE_ENC = 0x0B
INS_GET_SERVER_RSA_KEY = 0x06
INS_SET_SERVER_KEY = 0x05
INS_SET_PIN = 0x02

SERVER_URL = "http://127.0.0.1"  # Adresse du serveur de vérification

transaction_tmpTest = 0


def send_hello(connection):
    """Envoie la commande INS_HELLO à la carte et affiche le message."""
    apdu_hello = [CLA_PROJET, INS_HELLO, 0x00, 0x00, 0x00]
    data, sw1, sw2 = send_apdu_with_length_handling(connection, apdu_hello)

    if (sw1 << 8 | sw2) == SW_COMMAND_SUCCESS:
        try:
            message = bytes(data).decode('utf-8')
            print(f"Message de la carte : {message}")
        except UnicodeDecodeError:
            print(f"Données reçues (non décodables) : {toHexString(data)}")
    else:
        raise RuntimeError(f"La commande INS_HELLO a échoué. SW1: {sw1:02X}, SW2: {sw2:02X}")

def get_server_rsa_key(connection):
    """
    Récupère la clé publique RSA (exposant + module) du serveur depuis la carte et la transforme au format PEM. (uniquement pour test)
    """
    apdu_get_server_rsa_key = [CLA_PROJET, INS_GET_SERVER_RSA_KEY, 0x00, 0x00, 0x00]
    data, sw1, sw2 = send_apdu_with_length_handling(connection, apdu_get_server_rsa_key)

    if (sw1 << 8 | sw2) != SW_COMMAND_SUCCESS:
        raise RuntimeError(f"Échec de la récupération de la clé RSA du serveur. SW1: {sw1:02X}, SW2: {sw2:02X}")

    # Décoder l'exposant
    exp_len = data[0]  # Longueur de l'exposant
    exponent = data[1:1 + exp_len]

    # Décoder le module
    mod_len = data[1 + exp_len]  # Longueur du module
    modulus = data[1 + exp_len + 1:1 + exp_len + 1 + mod_len]

    # Vérifications
    if len(exponent) != exp_len or len(modulus) != mod_len:
        raise ValueError("Données de clé RSA incorrectes.")

    # Convertir les données hexadécimales en entiers
    exponent_int = int.from_bytes(exponent, 'big')
    modulus_int = int.from_bytes(modulus, 'big')

    # Créer un objet PublicKey de Python-RSA
    public_key = rsa.PublicKey(modulus_int, exponent_int)

    # Exporter la clé publique au format PEM
    public_key_pem = public_key.save_pkcs1(format='PEM').decode('utf-8')

    return public_key_pem

def set_pin(connection, pin):
    """Envoie le PIN pour initialiser la carte."""
    if len(pin) != 4 or not pin.isdigit():
        raise ValueError("Le PIN doit contenir exactement 4 chiffres.")
    pin_data = [ord(c) for c in pin]  # Convertir le PIN en octets
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


def get_server_ip(connection):
    """
    Envoie une commande APDU pour récupérer l'IP du serveur.
    """
    apdu = [CLA_PROJET, INS_GET_SERVER_IP, 0x00, 0x00, 0x00]
    ip_data, sw1, sw2 = send_apdu_with_length_handling(connection, apdu)

    if (sw1 << 8 | sw2) != SW_COMMAND_SUCCESS:
        raise RuntimeError(f"Erreur lors de la récupération de l'IP. SW1: {sw1:02X}, SW2: {sw2:02X}")

    # Convertir les octets en une chaîne lisible
    ip = "".join(map(chr, ip_data))

    print(f"Adresse IP : {ip}")
    return ip

def checkSign(ip_response, public_key_pem): 
    try:
        public_key = rsa.PublicKey.load_pkcs1(public_key_pem.encode('utf-8'))
    except Exception as e:
        print(f"Error loading public key: {e}")
        return False
    
    if len(ip_response) < 64:
        print("Response is too short to contain a valid signature.")
        return False

    try:
        # Extract signature and IP
        signature = ip_response[:64].encode('latin1')
        ip = ip_response[64:].encode('utf-8')   
        
        # Verify the signature
        rsa.verify(ip, signature, public_key)
        print("Signature de l'IP valide.")
        return ip.decode('utf-8'), True  # Decode IP back to string for return
    except rsa.VerificationError:
        print("Signature verification failed.")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False
    
def generate_string(nb):
    """
    Génère une chaîne de 255 octets composée de caractères alphanumériques.
    :return: Une chaîne de 255 octets.
    """
    import string
    import random

    # Créer une chaîne alphanumérique de 255 caractères
    characters = string.ascii_letters + string.digits  # Lettres (majuscules/minuscules) et chiffres
    result = ''.join(random.choices(characters, k=nb))  # Générer 255 caractères aléatoires
    return result



def pay(connection, description):
    """
    - Envoie les données de description au format multi-APDU.
    - Récupère le ciphertext en fragments.
    - Envoie le ciphertext au serveur.
    """
    # 1) Récupérer la date/heure depuis le serveur
    time_response = requests.get("http://127.0.0.1/time")
    time_response.raise_for_status()
    server_time = time_response.json()["time"]
    server_signature_base64 = time_response.json()["signature"]
    server_signature = base64.b64decode(server_signature_base64)

    # 2) Préparer les données
    if isinstance(description, list):
        description = ''.join(chr(byte) for byte in description)
    elif not isinstance(description, str):
        raise TypeError("Description must be a string or a list of bytes.")

    # Construire la chaîne avec la signature brute
    data_str = f"{server_time}|{description}"
    data_bytes = server_signature + data_str.encode('utf-8')  # Concaténer en bytes
    

    # 3 et 4 Utiliser la fonction générique pour gérer les APDU
    transaction = handle_multi_apdu(connection, INS_PAY, data=data_bytes)
    
    public_key_pem = get_rsa_key(connection)

    # 5) Vérification de la/les signature(s)
    try:
        is_valid=verify_transaction_blocks(transaction, public_key_pem)
    except Exception as e:
        print(f"Erreur : {str(e)}")

    if(is_valid):
        # 6) Récupérer l'adresse IP du serveur
        try:
            server_ip = get_server_ip(connection)
            server_ip, is_valid_signature = checkSign(server_ip, public_key_pem)
            if not is_valid_signature:
                raise RuntimeError("Signature de l'IP du serveur invalide.")
        except Exception as e:
            raise RuntimeError(f"Impossible de récupérer l'adresse IP du serveur : {e}")
        
        
        print(f"Adresse IP du serveur récupérée : {server_ip}")

        # 7) Envoyer la requête au serveur
        try:
            # Construire l'URL du serveur
            server_url = f"http://{server_ip}/transaction"

            # Encoder la transaction en Base64
            transaction_base64 = base64.b64encode(bytes(transaction)).decode('utf-8')

            # Envoyer la requête
            response = requests.post(server_url, json={
                "transaction": transaction_base64,
                "public_key": public_key_pem,
            })

            # Vérifier la réponse
            response.raise_for_status()
            print(f"Réponse du serveur : {response.json()}")
        except requests.RequestException as e:
            raise RuntimeError(f"Erreur lors de l'envoi de la requête au serveur : {e}")
    else:
        print("Erreur, signatures non valides")
    return transaction_base64

def decrypt_logs(connection, transactions):
    """
    Envoie une transaction encodée en base64 à la carte pour déchiffrement.

    :param connection: Connexion à la carte.
    :param transaction_b64: Transaction encodée en base64.
    :return: Données déchiffrées (bytes).
    """
    transaction_bytes = base64.b64decode(transactions)
    decrypted = handle_multi_apdu(connection, INS_DECRYPT_LOG, data=transaction_bytes)

    # Conversion en chaîne
    result = ''.join(chr(byte) for byte in decrypted)

    return result


def main():
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

        while True:
            print("\nMenu de test :")
            print("1. Envoyer un Hello à la carte")
            print("2. Initialiser un PIN (valable uniquement si le script init n'a pas été lancé et permet de vérifier qu'on ne peut pas le faire une deuxième fois)")
            print("3. Vérifier un PIN")
            print("4. Récupérer la clé RSA de la carte")
            print("5. Récupérer la clé RSA du serveur depuis la carte et vérifier avec celle du serveur")
            print("6. Récupérer l'adresse IP du serveur et vérifier la signature avec la clé publique du serveur stockée sur la carte")
            print("7. Crypter une nouvelle transaction et l'envoyer au serveur")
            print("8. Crypter une transaction aléatoire en choisisant la taille (notamment pour tester les chaines > 255 octets) et l'envoyer au serveur")
            print("9. Décrypter la dernière transaction chiffrée")
            print("10. Quitter")
            
            choix = input("Choisissez une option : ")
            
            try:
                if choix == "1":
                    send_hello(connection)
                elif choix == "2":
                    pin = input("Entrez un nouveau PIN (4 chiffres) (valable une seule fois): ")
                    set_pin(connection, pin)
                elif choix == "3":
                    pin = input("Entrez le PIN à vérifier : ")
                    verify_pin(connection, pin)
                elif choix == "4":
                    public_key = get_rsa_key(connection)
                    print(f"Clé publique de la carte : \n{public_key}")
                elif choix == "5":
                    pin = input("Entrez le PIN à vérifier : ")
                    try:
                        # Vérifier le PIN
                        verify_pin(connection, pin)

                        # Récupérer la clé publique du serveur depuis la carte
                        server_key_card = get_server_rsa_key(connection)
                        print(f"Clé publique du serveur depuis la carte : \n{server_key_card}")

                        # Récupérer la clé publique du serveur depuis le serveur
                        response = requests.get(f"{SERVER_URL}/public_key")
                        response.raise_for_status()
                        server_key_server = response.json()["public_key"]
                        print(f"Clé publique du serveur depuis le serveur : \n{server_key_server}")

                        # Comparer les deux clés
                        if server_key_card.strip() == server_key_server.strip():
                            print("Les deux clés publiques du serveur correspondent.")
                        else:
                            print("Les clés publiques du serveur ne correspondent pas.")
                    except Exception as e:
                        print(f"Erreur lors de la vérification du PIN ou de la comparaison des clés : {e}")
                elif choix == "6":
                    public_key_pem = get_rsa_key(connection)
                    try:
                        server_ip = get_server_ip(connection)
                        server_ip, is_valid_signature = checkSign(server_ip, public_key_pem)
                        if not is_valid_signature:
                            raise RuntimeError("Signature de l'IP du serveur invalide.")
                    except Exception as e:
                        raise RuntimeError(f"Impossible de récupérer l'adresse IP du serveur : {e}")
                    
                    print(f"Adresse IP du serveur récupérée : {server_ip}")
                elif choix == "7":
                    pin = input("Entrez le PIN à vérifier : ")
                    verify_pin(connection, pin)
                    description = input("Entrez une description de la transaction : ")
                    transactionBase64 = pay(connection, description)
                    if transactionBase64:
                        print(f"Transaction chiffrée et encodée en Base64 : \n{transactionBase64}")
                    else:
                        print("Échec du chiffrement de la transaction.")
                elif choix == "8":
                    pin = input("Entrez le PIN à vérifier : ")
                    verify_pin(connection, pin)
                    size = input("Saisir la taille de la chaîne : ")
                    if size.isdigit():
                        size = int(size)  # Convertir en entier
                        random_string = os.urandom(size).hex()
                        print('Chaîne à chiffrer :', random_string)
                        transactionBase64 = pay(connection, random_string)
                        if transactionBase64:
                            print(f"Transaction chiffrée et encodée en Base64 : \n{transactionBase64}")
                        else:
                            print("Échec du chiffrement de la transaction.")
                    else:
                        print("Veuillez réessayer et entrer un nombre valide.")
                elif choix == "9":
                    pin = input("Entrez le PIN à vérifier : ")
                    verify_pin(connection, pin)
                    if not transactionBase64:
                        print("Aucune transaction disponible. Veuillez d'abord effectuer une transaction (option 7).")
                    else:
                        decrypted_logs = decrypt_logs(connection, transactionBase64)
                        print(f"Dernière transaction déchiffrée : \n{decrypted_logs}")
                elif choix == "10":
                    print("Au revoir !")
                    break
                else:
                    print("Option invalide, veuillez réessayer.")
            except Exception as e:
                print(f"Erreur lors de l'exécution : {e}")

            # Confirmation pour retourner au menu
            input("\nAppuyez sur Entrée pour retourner au menu.")
    except Exception as e:
        print(f"Erreur : {e}")
    finally:
        connection.disconnect()

if __name__ == "__main__":
    main()



