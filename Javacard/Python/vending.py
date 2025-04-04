from smartcard.System import readers
import base64
import rsa
import requests
from utils import verify_transaction_blocks, CLA_PROJET, INS_GET_SERVER_IP, send_apdu_with_length_handling, SW_COMMAND_SUCCESS, handle_multi_apdu, INS_PAY, get_rsa_key, select_applet, verify_pin 

#Vérifie la signature d'un message
def checkSign(ip_response, public_key_pem): 
    try:
        # Chargement de la clé publique à partir du format PEM
        public_key = rsa.PublicKey.load_pkcs1(public_key_pem.encode('utf-8'))
    except Exception as e:
        print(f"Erreur lors du chargement de la clé publique : {e}")
        return False
    
    # Vérification que la réponse est suffisamment longue pour contenir une signature
    if len(ip_response) < 64:
        print("La réponse est trop courte pour contenir une signature valide.")
        return False

    try:
        # Extraction de la signature et de l'adresse IP
        signature = ip_response[:64].encode('latin1')  # Convertir la signature en bytes
        ip = ip_response[64:].encode('utf-8')         # Convertir la partie IP en bytes
        
        # Vérification de la signature
        rsa.verify(ip, signature, public_key)
        print("Signature de l'adresse IP valide.")
        return ip.decode('utf-8'), True  # Décoder l'adresse IP en chaîne de caractères pour le retour
    except rsa.VerificationError:
        print("Échec de la vérification de la signature.")
        return False
    except Exception as e:
        print(f"Erreur inattendue : {e}")
        return False
    

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




def main():
    available_readers = readers()
    if not available_readers:
        print("No card reader found.")
        return

    reader = available_readers[0]
    connection = reader.createConnection()

    try:
        connection.connect()
        select_applet(connection)

        # Verify PIN before proceeding
        pin = input("Enter PIN for verification: ")
        verify_pin(connection, pin)

        # Demander à l'utilisateur comment il veut envoyer les données
        print("Options d'envoi des données :")
        print("1. Saisir manuellement les données")
        print("2. Utiliser des transactions prédéfinies :")
        print("   - 'testTransaction' : une chaîne simple.")
        print("   - 'testTransaction2' : une chaîne répétée plusieurs fois pour dépasser 255 octets.")
        print("3. Charger un fichier contenant des données (fichier transaction.txt disponible)")


        choice = input("Choisissez une option (1, 2 ou 3) : ")

        if choice == "1":
            data = input("Entrez les données à envoyer : ")
            pay(connection, data)
        elif choice == "2":
            # Exemple avec testTransaction
            data = "testTransaction"
            pay(connection, data)

            # Exemple avec testTransaction2 (plus de 256 octets)
            data = "testTransaction2" * 20  # Multiplie la chaîne pour dépasser 256 octets
            pay(connection, data)
        elif choice == "3":
            file_path = input("Entrez le chemin du fichier contenant les données : ")
            try:
                with open(file_path, "r") as file:
                    data = file.read()
                pay(connection, data)
            except FileNotFoundError:
                print("Erreur : fichier introuvable.")
        else:
            print("Option invalide.")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
