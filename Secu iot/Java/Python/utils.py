import rsa

# Constantes nécessaires
CLA_PROJET = 0x42
INS_HELLO = 0x01
INS_SET_PIN = 0x02
INS_VERIFY_PIN = 0x03
INS_GET_RSA_KEY = 0x04
INS_SELECT = 0xA4
INS_GET_SERVER_IP = 0x08
INS_PAY = 0x09
INS_DECRYPT_LOG = 0x0A
INS_SIMPLE_ENC = 0x0B
APPLET_AID = [0xA0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x10, 0x01]
SW_COMMAND_SUCCESS = 0x9000
SW_WRONG_LENGTH = 0x6C




def send_apdu(connection, apdu):
    """Envoie une commande APDU et retourne la réponse."""
    data, sw1, sw2 = connection.transmit(apdu)
    return data, sw1, sw2

def select_applet(connection):
    """Sélectionne l'applet sur la carte."""
    select_apdu = [0x00, INS_SELECT, 0x04, 0x00, len(APPLET_AID)] + APPLET_AID
    data, sw1, sw2 = send_apdu(connection, select_apdu)
    if (sw1 << 8 | sw2) != SW_COMMAND_SUCCESS:
        raise RuntimeError(f"Échec de la sélection de l'applet. SW1: {sw1:02X}, SW2: {sw2:02X}")

def send_apdu_with_length_handling(connection, apdu):
    """
    Envoie une commande APDU à la carte, gère les erreurs de longueur (SW_WRONG_LENGTH)
    et retourne les données, SW1, SW2.
    """
    # Envoi initial de la commande APDU
    data, sw1, sw2 = send_apdu(connection, apdu)

    # Vérifie si une erreur de longueur a été renvoyée
    if sw1 == SW_WRONG_LENGTH:
        # Récupère la longueur correcte dans SW2 et renvoie la commande avec LE ajusté
        le = sw2
        apdu_corrected = apdu[:4] + [le]  # Remplace le champ LE dans l'APDU
        data, sw1, sw2 = send_apdu(connection, apdu_corrected)
    
    # Retourne les données et le statut final
    return data, sw1, sw2

def handle_multi_apdu(connection, instruction, data=None, p1_send=0x00, p1_receive=0x03):
    """
    Gère l'envoi et la réception multi-APDU pour une instruction donnée.
    
    :param connection: Connexion à la carte.
    :param instruction: Instruction (INS).
    :param data: Données à envoyer (peut être None pour juste recevoir).
    :param p1_send: P1 pour l'envoi initial (par défaut 0x00).
    :param p1_receive: P1 pour la réception (par défaut 0x03).
    :return: Données reçues de la carte.
    """
    chunk_size = 255
    offset = 0
    received_data = []

    # Si des données sont fournies, les envoyer
    if data:
        total_len = len(data)
        # Premier fragment
        length_high = (total_len >> 8) & 0xFF
        length_low = total_len & 0xFF
        first_chunk = data[:chunk_size-2]
        apdu_data = [length_high, length_low] + list(first_chunk)
        apdu = [CLA_PROJET, instruction, p1_send, 0x00, len(apdu_data)] + apdu_data
        _, sw1, sw2 = send_apdu(connection, apdu)
        if (sw1 << 8 | sw2) != SW_COMMAND_SUCCESS:
            raise RuntimeError(f"Erreur lors de l'envoi du premier fragment : SW1={sw1:02X}, SW2={sw2:02X}")
        offset += len(first_chunk)

        # Fragments intermédiaires
        while offset < total_len:
            next_offset = offset + chunk_size
            chunk = data[offset:next_offset]
            p1 = 0x01 if next_offset < total_len else 0x02
            apdu_data = list(chunk)
            apdu = [CLA_PROJET, instruction, p1, 0x00, len(apdu_data)] + apdu_data
            _, sw1, sw2 = send_apdu(connection, apdu)
            if (sw1 << 8 | sw2) != SW_COMMAND_SUCCESS:
                raise RuntimeError(f"Erreur lors de l'envoi d'un fragment : SW1={sw1:02X}, SW2={sw2:02X}")
            offset = next_offset
        

    chunk_size += 1
    # Lecture de la longueur totale des données à recevoir
    apdu = [CLA_PROJET, instruction, p1_receive, 0x00, chunk_size]  # Demande le premier fragment
    data, sw1, sw2 = send_apdu_with_length_handling(connection, apdu)
    

    # Extraction de la longueur totale depuis les 2 premiers octets
    if len(data) < 2:
        raise RuntimeError("Réponse trop courte pour inclure la longueur totale.")
    total_length = (data[0] << 8) | data[1]

    # Conserver le premier fragment des données chiffrées (après les 2 octets de longueur)
    received_data = data[2:]
    # Récupération des fragments suivants
    while len(received_data) < total_length:
        apdu = [CLA_PROJET, instruction, p1_receive, 0x00, chunk_size]  # Demande un fragment
        data, sw1, sw2 = send_apdu_with_length_handling(connection, apdu)
        received_data.extend(data)
        if (sw1 << 8 | sw2) == SW_COMMAND_SUCCESS:
            continue
        elif (sw1 << 8 | sw2) != 0x6100:
            raise RuntimeError(f"Erreur lors de la réception des fragments : SW1={sw1:02X}, SW2={sw2:02X}")
        
    return received_data

def verify_pin(connection, pin):
    """Verify the PIN on the card."""
    pin_data = [ord(c) for c in pin]
    apdu_verify_pin = [CLA_PROJET, INS_VERIFY_PIN, 0x00, 0x00, len(pin_data)] + pin_data
    _, sw1, sw2 = send_apdu(connection, apdu_verify_pin)

    if (sw1 << 8 | sw2) != SW_COMMAND_SUCCESS:
        raise RuntimeError(f"PIN verification failed. SW1: {sw1:02X}, SW2: {sw2:02X}")

    print("PIN verified successfully.")

def get_rsa_key(connection):
    """
    Récupère la clé publique RSA (exposant + module) depuis la carte et la transforme au format PEM.
    """
    apdu_get_rsa_key = [CLA_PROJET, INS_GET_RSA_KEY, 0x00, 0x00, 0x00]
    data, sw1, sw2 = send_apdu_with_length_handling(connection, apdu_get_rsa_key)

    if (sw1 << 8 | sw2) != SW_COMMAND_SUCCESS:
        raise RuntimeError(f"Échec de la récupération de la clé RSA. SW1: {sw1:02X}, SW2: {sw2:02X}")

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

def verify_transaction_blocks(transaction, public_key_pem):
    """
    Vérifie la signature de chaque bloc de la transaction.
    
    :param transaction: Données de la transaction (en bytes).
    :param public_key_pem: Clé publique RSA au format PEM.
    """

    SIGNATURE_LENGTH = 64
    BLOCK_LENGTH = SIGNATURE_LENGTH * 2  # 64 octets de signature + 64 octets de message chiffré

    # Vérifier que la transaction est un multiple de la taille d'un bloc
    if len(transaction) % BLOCK_LENGTH != 0:
        return False

    # Charger la clé publique
    try:
        public_key = rsa.PublicKey.load_pkcs1(public_key_pem.encode('utf-8'))
    except Exception as e:
        return False
    
    
    # Parcourir chaque bloc et vérifier la signature
    for i in range(0, len(transaction), BLOCK_LENGTH):
        block = transaction[i:i + BLOCK_LENGTH]

        signature = bytes(block[:SIGNATURE_LENGTH])  # Signature (64 octets)
        message = bytes(block[SIGNATURE_LENGTH:])   # Message chiffré (64 octets)
        
        try:
            rsa.verify(message, signature, public_key)
            print(f"Bloc {i // BLOCK_LENGTH + 1}: Signature valide.")
        except rsa.VerificationError:
            return False

    return True