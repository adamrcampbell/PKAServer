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
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.PBEParameterSpec;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Iterator;

@Singleton
public class ClientData implements ClientDataLocal {

    // Agreed salt between client and PKA
    private final byte[] salt = {-84, 40, -10, -53, -80, 90, -57, 125};
    // Client maps
    private Map<String, String> requests;
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
    public String getAllNumbers(String mobile, String cipher) {

        String numbers = null;

        // Is client active?
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
                String nonce = new String(plainBytes); // mobile num of client

                // Is nonce same as client mobile num?
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

                    // Encode for transport
                    numbers = Utility.encodeToBase64(numbers.getBytes());
                    
                    return numbers;
                }

                // Return empty data, nonce was not accepted
                return numbers;
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(ClientData.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
                Logger.getLogger(ClientData.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(ClientData.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(ClientData.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(ClientData.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        // Return empty data, client was not active client
        return numbers;
    }

    @Override
    public String getPublicKey(String mobile, String cipher) {

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
                String recipientNum = new String(plainBytes); // mobile num of requested client

                if (clients.containsKey(recipientNum)) {
                    // Get recipient key
                    PublicKey recipientKey = clients.get(recipientNum);
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
        // Return nothing, client doesnt exist
        return key;
    }

    @Override
    public String joinServer(String mobile, String cipher) {

        System.out.println("Receieved Join: " + cipher);
        System.out.println("Length: " + cipher.length());

        try {
            // Decode from transport
            byte[] decodedBytes = Utility.decodeFromBase64(cipher);

            // Get one time key for mobile number
//            String oneTimeKey = requests.get(mobile);
//
//            // Decrypt bytes using ephemeral key
//            char[] password = oneTimeKey.toCharArray();
//            PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, 1000);
//            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
//            SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
//
//            PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 1000);
//
//            Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES/CBC/PKCS5Padding");
//            pbeCipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
//            byte[] decryptBytes = pbeCipher.doFinal(decodedBytes);
//
//            // Get data from ciphertext
//            String[] data = new String(decryptBytes).split("---");
//            String phoneNum = data[0];
//            byte[] nonceBytes = Base64.getDecoder().decode(data[1].getBytes());
//            byte[] pubKeyBytes = Base64.getDecoder().decode(data[2].getBytes());
            
            PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decodedBytes));
                
            if(requests.containsKey(mobile))
                requests.remove(mobile);
            clients.put(mobile, pubKey);
            
            // Modify nonce
            int nonceNum = Integer.parseInt(mobile);
            nonceNum /= 2; // Divide by 2
            // Encrypt nonce and public key of PKA using public key of client
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(String.valueOf(nonceNum).getBytes()); // Modified Nonce

            // Encrypt data with pub key of client (added security)
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, pubKey);
            byte[] response = rsaCipher.doFinal(baos.toByteArray());
            // Encode for transport and return
            return Utility.encodeToBase64(response);
            
//            // Open nonceBytes to get nonce data
//            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//            rsaCipher.init(Cipher.DECRYPT_MODE, pubKey);
//            byte[] nonce = rsaCipher.doFinal(nonceBytes);
//
//            // Does nonce match?
//            if (new String(nonce).equals(phoneNum)) {
//                // Remove from temp requests
//                requests.remove(phoneNum);
//                // Add to active clients
//                clients.put(phoneNum, pubKey);
//                // Modify nonce
//                int nonceNum = Integer.parseInt(new String(nonce));
//                nonceNum %= 2; // Mod the value
//                // Encrypt nonce and public key of PKA using public key of client
//                ByteArrayOutputStream baos = new ByteArrayOutputStream();
//                baos.write(String.valueOf(nonceNum).getBytes()); // Modified Nonce
//                baos.write("---".getBytes());
//                baos.write(Base64.getEncoder().encode(publicKey.getEncoded())); // PKA pub key
//
//                // Encrypt data with pub key of client (added security)
//                rsaCipher.init(Cipher.ENCRYPT_MODE, pubKey);
//                byte[] response = rsaCipher.doFinal(baos.toByteArray());
//                // Encode for transport and return
//                return Utility.encodeToBase64(response);
//            }
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
        } catch (IOException ex) {
            Logger.getLogger(ClientData.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    @Override
    public String requestOneTimeKey(String mobile) {
        
        // Generate random one time password
        String password = generateOneTimePassword();
        // Add to requests mapping
        requests.put(mobile, password);        
        System.out.println("Request to join");
        System.out.println("Phone Number: " + mobile);
        System.out.println("Password: " + password);
        return password;
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
            char[] passwordCharArr = password.toCharArray();
            PBEKeySpec pbeSpec = new PBEKeySpec(passwordCharArr, salt, 1000);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            key = keyFactory.generateSecret(pbeSpec);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
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
