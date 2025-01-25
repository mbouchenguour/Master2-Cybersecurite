package notreprojet;

import com.sun.corba.se.spi.ior.IdentifiableContainerBase;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
import sun.reflect.CallerSensitive;

public class NotreProjet extends Applet {

    private static final byte[] helloWorld = {'H', 'e', 'l', 'l', 'o'};
    private static final byte[] SERVER_IP = {
            (byte) '1', (byte) '2', (byte) '7', (byte) '.', (byte) '0', (byte) '.', (byte) '0', (byte) '.', (byte) '1'
    };

    private static final byte CLA_PROJECT = (byte) 0x42;
    private static final byte INS_HELLO = (byte) 0x01;
    private static final byte INS_SET_PIN = (byte) 0x02;
    private static final byte INS_VERIFY_PIN = (byte) 0x03;
    private static final byte INS_GET_RSA_KEY = (byte) 0x04;
    private static final byte INS_STORE_SERVER_KEY = (byte) 0x05;
    private static final byte INS_GET_SERVER_RSA_KEY = (byte) 0x06;
    private static final byte INS_GET_SERVER_IP = (byte) 0x08; // Instruction pour récupérer l'IP du serveur
    private static final byte INS_PAY = (byte) 0x09;
    private static final byte INS_DECRYPT_LOG = (byte) 0x0A;


    private OwnerPIN pin;

    private KeyPair rsaKeyPair;

    private RSAPublicKey serverPublicKey;

    private boolean isInitialized;



    // Limites du PIN
    private static final byte PIN_TRY_LIMIT = 3;
    private static final byte PIN_LENGTH = 4;

    // Taille des clés RSA
    private static final short RSA_KEY_SIZE = 512;



    private static final short MAX_CHUNK_SIZE = 255;

    private byte[] globalBuffer;
    private byte[] tmpBuf;
    private byte[] payCipherBuffer;
    private byte[] toTransmitBuffer;

    private short globalOffset; // Offset pour suivre la progression
    private short expectedLength; // Longueur totale attendue
    private boolean isReceiving; // Indicateur d'état pour la réception

    protected NotreProjet() {
        pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_LENGTH);

        rsaKeyPair = new KeyPair(KeyPair.ALG_RSA_CRT, RSA_KEY_SIZE);
        rsaKeyPair.genKeyPair();

        tmpBuf = new byte[128];
        payCipherBuffer = new byte[64];

        globalBuffer = new byte[10240];
        toTransmitBuffer = new byte[10240];

        isInitialized = false;
        globalOffset = 0;
        expectedLength = 0;
        isReceiving = false;

        register();

    }

    private void resetBuffers() {
        globalOffset = 0;
        expectedLength = 0;
        isReceiving = false;

    }


    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new NotreProjet();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        byte CLA = buffer[ISO7816.OFFSET_CLA];
        byte INS = buffer[ISO7816.OFFSET_INS];
        if (CLA != CLA_PROJECT) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        switch (INS) {
            case INS_HELLO:
                getHelloWorld(apdu);
                break;
            case INS_SET_PIN:
                setPin(apdu);
                break;
            case INS_VERIFY_PIN:
                verifyPin(apdu);
                break;
            case INS_GET_RSA_KEY:
                getRSAKey(apdu);
                break;
            case INS_STORE_SERVER_KEY:
                storeServerKey(apdu);
                break;
            case INS_GET_SERVER_RSA_KEY:
                getServeurRSAKey(apdu);
                break;
            case INS_GET_SERVER_IP:
                getServerIP(apdu);
                break;
            case INS_PAY:
                pay(apdu);
                break;
            case INS_DECRYPT_LOG:
                decryptLog(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }



    private void getServerIP(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short offset = 0;

        RSAPrivateKey privateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
        Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        signature.init(privateKey, Signature.MODE_SIGN);


        short sigLen = signature.sign(SERVER_IP, (short) 0, (short) SERVER_IP.length, buffer, offset);
        offset += sigLen;

        // Copier l'adresse IP dans le tampon
        Util.arrayCopyNonAtomic(SERVER_IP, (short) 0, buffer, (short) offset, (short) SERVER_IP.length);
        offset += SERVER_IP.length;

        // Envoyer les données
        apdu.setOutgoingAndSend((short) 0, offset);
    }

    private void getHelloWorld(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short length = (short) helloWorld.length;
        Util.arrayCopyNonAtomic(helloWorld, (short) 0, buffer, (short) 0, length);
        apdu.setOutgoingAndSend((short) 0, length);
    }

    private void setPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if(!isInitialized){
            if (lc != PIN_LENGTH) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            isInitialized = true;
            pin.update(buffer, ISO7816.OFFSET_CDATA, (byte) lc);
        }else {
            // Si déjà initialisé, renvoie une exception pour signaler l'opération interdite
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

    }

    private void verifyPin(APDU apdu) {

        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();

        if (lc != PIN_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }


        if (!pin.check(buffer, ISO7816.OFFSET_CDATA, (byte) lc)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }


    private void getRSAKey(APDU apdu) {
        RSAPublicKey publicKey = (RSAPublicKey) rsaKeyPair.getPublic();

        byte[] buffer = apdu.getBuffer();
        short offset = 0;

        short expLen = publicKey.getExponent(buffer, (short) (offset + 1)); // Laisser 1 octet pour la longueur
        buffer[offset] = (byte) expLen; // Stocker la longueur de l'exposant
        offset += 1 + expLen;

        // Encodage du module
        short modLen = publicKey.getModulus(buffer, (short) (offset + 1)); // Laisser 1 octet pour la longueur
        buffer[offset] = (byte) modLen; // Stocker la longueur du module
        offset += 1 + modLen;

        // Envoi des données
        apdu.setOutgoingAndSend((short) 0, offset);
    }

    private void getServeurRSAKey(APDU apdu) {
        // Vérification que le PIN a été validé
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // Vérification que la clé publique du serveur est initialisée
        if (serverPublicKey == null) {
            ISOException.throwIt((short) 0x6A85); // Clé publique du serveur non configurée
        }

        byte[] buffer = apdu.getBuffer();
        short offset = 0;

        // Récupérer l'exposant de la clé publique du serveur
        short expLen = serverPublicKey.getExponent(buffer, (short) (offset + 1)); // Laisser 1 octet pour la longueur
        buffer[offset] = (byte) expLen; // Stocker la longueur de l'exposant
        offset += 1 + expLen;

        // Récupérer le module de la clé publique du serveur
        short modLen = serverPublicKey.getModulus(buffer, (short) (offset + 1)); // Laisser 1 octet pour la longueur
        buffer[offset] = (byte) modLen; // Stocker la longueur du module
        offset += 1 + modLen;

        // Envoyer les données au terminal
        apdu.setOutgoingAndSend((short) 0, offset);
    }


    private void storeServerKey(APDU apdu) {
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive(); // Longueur totale des données reçues

        // Offset initial pour les données
        short offset = ISO7816.OFFSET_CDATA;

        // Lire la longueur de l'exposant
        short expLen = (short) (buffer[offset++] & 0xFF);
        if (expLen <= 0 || expLen > 3) {
            ISOException.throwIt((short) 0x6A81); // Longueur d'exposant invalide
        }

        // Initialiser la clé publique si nécessaire
        serverPublicKey = (RSAPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_RSA_PUBLIC,
                KeyBuilder.LENGTH_RSA_512,
                false
        );

        // Charger l'exposant
        try {
            serverPublicKey.setExponent(buffer, offset, expLen);
        } catch (CryptoException e) {
            ISOException.throwIt((short) 0x6A82); // Erreur lors de la configuration de l'exposant
        }
        offset += expLen;

        // Lire la longueur du module
        short modLen = (short) (buffer[offset++] & 0xFF);
        if (modLen <= 0 || modLen > 128) { // Hypothèse : clé de 1024 bits max
            ISOException.throwIt((short) 0x6A83); // Longueur de module invalide
        }

        // Charger le module
        try {
            serverPublicKey.setModulus(buffer, offset, modLen);
        } catch (CryptoException e) {
            ISOException.throwIt((short) 0x6A84); // Erreur lors de la configuration du module
        }

        // Validation finale
        if ((short) (offset + modLen) != (short) (ISO7816.OFFSET_CDATA + lc)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
    }


    private void handleMultiAPDU(APDU apdu, byte p1) {
        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();

        if (p1 == 0) {
            // Premier fragment
            if (lc < 2) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            globalOffset = 0;
            expectedLength = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
            //globalBuffer = new byte[expectedLength];
            short dataLength = (short) (lc - 2);
            Util.arrayCopyNonAtomic(buffer, (short) (ISO7816.OFFSET_CDATA + 2), globalBuffer, globalOffset, dataLength);
            globalOffset += dataLength;
            isReceiving = true;

        } else if (p1 == 1) {
            // Fragment intermédiaire
            if (!isReceiving) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, globalBuffer, globalOffset, lc);
            globalOffset += lc;
            if (globalOffset > expectedLength) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

        } else if (p1 == 2) {
            // Dernier fragment
            if (!isReceiving) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, globalBuffer, globalOffset, lc);
            globalOffset += lc;
            if (globalOffset != expectedLength) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }


        }
    }




    private void pay(APDU apdu) {
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1];

        handleMultiAPDU(apdu, p1); // Gère la réception multi-APDU

        if (p1 == 2 || (p1 == 0 && expectedLength <= MAX_CHUNK_SIZE-2)) {
            RSAPublicKey publicKey = (RSAPublicKey) rsaKeyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

            Cipher cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
            Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);

            cipher.init(publicKey, Cipher.MODE_ENCRYPT);
            signature.init(privateKey, Signature.MODE_SIGN);

            Signature signatureServeur = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
            signatureServeur.init(serverPublicKey, Signature.MODE_VERIFY);

            // Vérification de la signature
            if (expectedLength < 64 + 19) { // 64 octets de signature et 19 pour la date
                ISOException.throwIt(ISO7816.SW_DATA_INVALID); // Données insuffisantes
            }

            // Vérification de la signature
            boolean isValid = signatureServeur.verify(
                    globalBuffer, (short) 64, (short)19, // Horodatage
                    globalBuffer, (short)0, (short)64 // Signature
            );

            if (!isValid) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED); // Signature invalide
            }



            // Étape 2 : Chiffrement et signature des blocs
            short blockSize = 53; // Taille max d'un bloc pour RSA 512 bits
            short totalLength = expectedLength;
            short offset = (short) 64;
            short outputOffset = 0;

            // Calcul du nombre de blocs nécessaires sans division
            short numBlocks = 0;
            short remaining = (short) (totalLength - 64);
            while (remaining > 0) {
                remaining -= blockSize; // Réduire la taille restante
                numBlocks++; // Augmenter le nombre de blocs
            }

            // Vérification de la taille totale requise
            short singleBlockSize = 128; // Taille totale d'un bloc (chiffré + signé)
            short requiredSize = (short) (numBlocks * singleBlockSize);
            // Allocation du tableau
            //toTransmitBuffer = new byte[requiredSize];

            // Parcourir et traiter chaque bloc
            while (offset < totalLength) {
                // Calculer la taille du bloc actuel
                short currentBlockSize;
                if ((short) (totalLength - offset) > blockSize) {
                    currentBlockSize = blockSize;
                } else {
                    currentBlockSize = (short) (totalLength - offset);
                }

                // Chiffrement du bloc
                short encLen = cipher.doFinal(globalBuffer, offset, currentBlockSize, tmpBuf, (short) 0);

                // Signature du bloc chiffré
                short sigLen = signature.sign(tmpBuf, (short) 0, encLen, payCipherBuffer, (short) 0);

                // Copier la signature dans le buffer de transmission
                Util.arrayCopyNonAtomic(payCipherBuffer, (short) 0, toTransmitBuffer, outputOffset, sigLen);
                outputOffset += sigLen;

                // Copier le bloc chiffré dans le buffer de transmission
                Util.arrayCopyNonAtomic(tmpBuf, (short) 0, toTransmitBuffer, outputOffset, encLen);
                outputOffset += encLen;

                // Mettre à jour l'offset de lecture
                offset += currentBlockSize;
            }


            // Étape 3 : Réinitialiser l'état pour le transfert fragmenté
            expectedLength = outputOffset;
            globalOffset = 0;
            isReceiving = false; // Fin de la réception

        }
        else if (p1 == 3) {
            // Envoi du ciphertext au terminal
            if (globalOffset == 0) {
                // Ajoutez la longueur totale des données dans les 2 premiers octets
                short le = apdu.setOutgoing();
                short toSend = (short) (expectedLength - globalOffset);

                // Vérifiez que la longueur à envoyer est suffisante pour inclure les 2 octets
                if (toSend > (short) (le - (short) 2)) {
                    toSend = (short) (le - (short) 2); // Ajuster pour inclure les 2 octets
                }

                apdu.setOutgoingLength((short) (toSend + (short) 2)); // Inclure les 2 octets dans la longueur totale
                Util.setShort(buffer, (short) 0, expectedLength); // Ajouter la longueur totale dans les 2 premiers octets
                Util.arrayCopyNonAtomic(toTransmitBuffer, globalOffset, buffer, (short) 2, toSend); // Copier les données après les 2 octets

                apdu.sendBytes((short) 0, (short) (toSend + 2)); // Envoyer les octets, y compris les 2 octets de longueur
                globalOffset += toSend; // Mettre à jour l'offset
            } else {
                // Comportement pour les fragments suivants
                short le = apdu.setOutgoing();
                short toSend = (short) (expectedLength - globalOffset);

                if (toSend > le) {
                    toSend = le; // Limiter à la longueur maximale disponible
                }

                apdu.setOutgoingLength(toSend);
                Util.arrayCopyNonAtomic(toTransmitBuffer, globalOffset, buffer, (short) 0, toSend); // Copier directement les données
                apdu.sendBytes((short) 0, toSend); // Envoyer le fragment
                globalOffset += toSend; // Mettre à jour l'offset

                if (globalOffset >= expectedLength) {
                    resetBuffers(); // Réinitialiser une fois tous les fragments envoyés
                }
            }

        }
    }

    private void decryptLog(APDU apdu) {
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1];

        handleMultiAPDU(apdu, p1); // Gère la réception multi-APDU

        if (p1 == 2 || (p1 == 0 && expectedLength <= MAX_CHUNK_SIZE-2)) {

            RSAPublicKey publicKey = (RSAPublicKey) rsaKeyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

            Cipher cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
            Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);

            // Utiliser la clé privée pour décrypter
            cipher.init(privateKey, Cipher.MODE_DECRYPT);

            // Utiliser la clé publique pour vérifier la signature
            signature.init(publicKey, Signature.MODE_VERIFY);

            // Étape 2 : Chiffrement et signature des blocs
            short blockSize = 128; // Taille d'un bloc : 64 octets de signature + 64 octets de données chiffrées
            short totalLength = expectedLength;
            short offset = 0;
            short outputOffset = 0;

            // Vérification de la taille totale requise
            if (totalLength % blockSize != 0) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID); // Données corrompues ou mal formatées
            }

            // Allocation d'un tampon pour la sortie déchiffrée
            //toTransmitBuffer = new byte[expectedLength];

            while (offset < expectedLength) {
                // Vérification de la taille des blocs
                if ((short) (expectedLength - offset) < blockSize) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID); // Bloc incomplet
                }

                // Lecture du bloc actuel
                Util.arrayCopyNonAtomic(globalBuffer, offset, tmpBuf, (short) 0, blockSize);

                // Vérification de la signature
                boolean isValid = signature.verify(tmpBuf, (short) 64, (short) 64, tmpBuf, (short) 0, (short) 64);
                if (!isValid) {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED); // Signature invalide
                }

                // Déchiffrement des données (64 octets après la signature)
                short decLen = cipher.doFinal(tmpBuf, (short) 64, (short) 64, toTransmitBuffer, outputOffset);

                // Mise à jour des offsets
                outputOffset += decLen;
                offset += blockSize;
            }

            // Réinitialisation pour le transfert fragmenté
            expectedLength = outputOffset;
            globalOffset = 0;
            isReceiving = false; // Réinitialisation de l'état

        }
        else if (p1 == 3) {
            // Envoi du ciphertext au terminal
            if (globalOffset == 0) {
                // Ajoutez la longueur totale des données dans les 2 premiers octets
                short le = apdu.setOutgoing();
                short toSend = (short) (expectedLength - globalOffset);

                // Vérifiez que la longueur à envoyer est suffisante pour inclure les 2 octets
                if (toSend > (short) (le - 2)) {
                    toSend = (short) (le - 2); // Ajuster pour inclure les 2 octets
                }

                apdu.setOutgoingLength((short) (toSend + 2)); // Inclure les 2 octets dans la longueur totale
                Util.setShort(buffer, (short) 0, expectedLength); // Ajouter la longueur totale dans les 2 premiers octets
                Util.arrayCopyNonAtomic(toTransmitBuffer, globalOffset, buffer, (short) 2, toSend); // Copier les données après les 2 octets

                apdu.sendBytes((short) 0, (short) (toSend + 2)); // Envoyer les octets, y compris les 2 octets de longueur
                globalOffset += toSend; // Mettre à jour l'offset
            } else {
                // Comportement pour les fragments suivants
                short le = apdu.setOutgoing();
                short toSend = (short) (expectedLength - globalOffset);

                if (toSend > le) {
                    toSend = le; // Limiter à la longueur maximale disponible
                }

                apdu.setOutgoingLength(toSend);
                Util.arrayCopyNonAtomic(toTransmitBuffer, globalOffset, buffer, (short) 0, toSend); // Copier directement les données
                apdu.sendBytes((short) 0, toSend); // Envoyer le fragment
                globalOffset += toSend; // Mettre à jour l'offset

                if (globalOffset >= expectedLength) {
                    resetBuffers(); // Réinitialiser une fois tous les fragments envoyés
                }
            }
        }

    }


}
