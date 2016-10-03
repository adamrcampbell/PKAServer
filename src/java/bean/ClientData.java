package bean;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.ejb.Singleton;
import client.Client;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Iterator;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

@Singleton
public class ClientData implements ClientDataLocal {

    // Agreed salt between client and PKA
    private final byte[] IV = {-84, 40, -10, -53, -80, 90, -57, 125, -84, 40, -10, -53, -80, 90, -57, 125};
    // Client maps
    private Map<String, SecretKey> requests;
    private Map<String, PublicKey> clients;
    // PKA Keys
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ClientData() {

        requests = new HashMap<>();
        clients = new HashMap<>();
        // Populate keys if not yet done
        if (publicKey == null && privateKey == null) {
            generateKeys();
        }
    }

    @Override
    public String getAllNumbers(String mobile, String cipher, String validation) {

        String numbers = "";

        // Is client active?
        if (clients.containsKey(mobile)) {
            PublicKey pubKey = clients.get(mobile);
            byte[] cipherBytes = Utility.decodeFromBase64(cipher);
            byte[] outer = Utility.decryptRSA(privateKey, cipherBytes);
            //byte[] inner = Utility.decryptRSA(pubKey, cipherBytes);
            String nonce = new String(outer);
            if (nonce.equals(mobile)) {
                // Get client keys
                Iterator<String> clientKeys = clients.keySet().iterator();
                // Get client numbers data
                while (clientKeys.hasNext()) {
                    numbers += clientKeys.next();
                    
                    if (clientKeys.hasNext()) {
                        numbers += ",";
                    }
                }
                
                // Add RSA encryption here
                outer = Utility.encryptRSA(pubKey, numbers.getBytes());
                //outer = Utility.encryptRSA(privateKey, outer);
                String encoded = Utility.encodeToBase64(outer);
                
                return encoded;
            }
            return numbers;
        }
        // Return empty data, client was not active client
        return numbers;
    }

    @Override
    public String getPublicKey(String mobile, String cipher, String validation) {
        
        System.out.println("Request for " + mobile + " Public key");
        String key = null;

        if (clients.containsKey(mobile)) {

            try {
                // Get pub key
                PublicKey pubKey = clients.get(mobile);
                // Decode from transport
                byte[] cipherBytes = Utility.decodeFromBase64(cipher);
                // Decrypt RSA
                Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                rsaCipher.init(Cipher.DECRYPT_MODE, pubKey);
                byte[] plainBytes = rsaCipher.doFinal(cipherBytes);
                // Get contents from bytes
                String contactMob = new String(plainBytes); // mobile num of requested client
                
                System.out.println("Contact Reqested: " + contactMob);
                
                if (clients.containsKey(contactMob)) {
                    // Get recipient key
                    PublicKey recipientKey = clients.get(contactMob);
                    // Set cipher to encrypt via pka pri key
                    rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);
                    byte[] pkaBytes = rsaCipher.doFinal(recipientKey.getEncoded());
                    // Set cipher to encrypt via client pub key
                    rsaCipher.init(Cipher.ENCRYPT_MODE, pubKey);
                    byte[] clientBytes = rsaCipher.doFinal(pkaBytes);
                    // Encode for transport
                    key = Utility.encodeToBase64(clientBytes);

                    return key;
                }
                else
                {
                    System.out.println("Contact Key Isnt registered");
                }
                // Return nothing, recipient doesnt exist 
                return key;
            } catch (InvalidKeyException ex) {
                Logger.getLogger(ClientData.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(ClientData.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(ClientData.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(ClientData.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
                Logger.getLogger(ClientData.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        else
        {
            System.out.println("Client Key isnt registered");
        }
        // Return nothing, client doesnt exist
        return key;
    }

    @Override
    public String joinServer(String mobile, String cipher, String validation) {

        System.out.println("Receieved Join: " + cipher);
        System.out.println("Length: " + cipher.length());

        try {
            // Decode from transport
            byte[] decodedBytes = Utility.decodeFromBase64(cipher);

            // Get one time key for mobile number
            SecretKey ephemeral = requests.get(mobile);
            
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec initVector = new IvParameterSpec(IV);
            // initialize cipher for encryption
            aesCipher.init(Cipher.DECRYPT_MODE, ephemeral, initVector);
            
            byte[] decryptBytes = aesCipher.doFinal(decodedBytes);

            // Get data from ciphertext
            String[] data = new String(decryptBytes).split("---");
            String phoneNum = data[0];
            byte[] nonceBytes = Base64.getDecoder().decode(data[1].getBytes());
            byte[] pubKeyBytes = Base64.getDecoder().decode(data[2].getBytes());
            
            PublicKey clientPubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubKeyBytes));
                
            // Open nonceBytes to get nonce data
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] nonce = rsaCipher.doFinal(nonceBytes);

            // Does nonce match?
            if (new String(nonce).equals(phoneNum)) {
                // Remove from temp requests
                requests.remove(phoneNum);
                // Add to active clients
                clients.put(phoneNum, clientPubKey);
                // Modify nonce
//                int nonceNum = Integer.parseInt(new String(nonce));
//                nonceNum /= 2; // Mod the value
//                // Encrypt nonce and public key of PKA using public key of client
//                ByteArrayOutputStream baos = new ByteArrayOutputStream();
//                baos.write(nonceNum); // Modified Nonce
//
//                // Encrypt data with pub key of client (added security)
//                rsaCipher.init(Cipher.ENCRYPT_MODE, clientPubKey);
//                byte[] inner = rsaCipher.doFinal(baos.toByteArray());
//
//                // Encrypt with private key of pka
//                rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);
//                byte[] outer = rsaCipher.doFinal(inner);
//                // Encode for transport and return
//                return Utility.encodeToBase64(outer);
                return "Success";
            }
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ClientData.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(ClientData.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(ClientData.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(ClientData.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(ClientData.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(ClientData.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(ClientData.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    @Override
    public String requestOneTimeKey(String mobile) {
        
        // Generate random one time password
        String password = generateOneTimePassword();
        SecretKey ephemeral = generateEphemeral(password);
        
        String ephemeralBase64 = Utility.encodeToBase64(ephemeral.getEncoded());
        // Add to requests mapping
        requests.put(mobile, ephemeral);        
        System.out.println("Request to join");
        System.out.println("Phone Number: " + mobile);
        System.out.println("Password: " + ephemeralBase64);
        return ephemeralBase64;
    }

    private void generateKeys() {

        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair keyPair = kpg.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private String generateOneTimePassword() {

        Random rand = new Random();

        String[] fruits = {"Pineapple", "Raspberry", "Passionfruit", "Tangerine", "Coconut", "Avocado",
            "Rockmelon", "Banana", "Kiwifruit", "Watermelon"};
        int randNum = rand.nextInt(9999 - 1000) + 1000;

        // Generate one time key
        return fruits[rand.nextInt(fruits.length)] + randNum;
    }

    private SecretKey generateEphemeral(String password) {

        SecretKey key = null;

        try {
//            char[] passwordCharArr = password.toCharArray();
//            PBEKeySpec pbeSpec = new PBEKeySpec(passwordCharArr, salt, 1000);
//            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("AES");
//            key = keyFactory.generateSecret(pbeSpec);
//            
            
            // generate a secret key for AES
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128); // 128-bit key used for AES
            key = kg.generateKey();
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }

        return key;
    }

    @Override
    public String getPkaPublicKey() {

        // Populate keys if not populated
        if (publicKey == null && privateKey == null) {
            generateKeys();
        }
        // Base 64 encode key
        String pubkey = Utility.encodeToBase64(publicKey.getEncoded());
        // Return base64 & HTML encoded pka pub key
        return pubkey;
    }
    
}
