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
import java.util.Properties;
import java.util.Set;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

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
                // Decode cipher
                cipher = htmlDecode(cipher);
                // Base64 decode
                byte[] cipherBytes = Base64.getDecoder().decode(cipher);
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

                    // Base 64 encode
                    numbers = Base64.getEncoder().encodeToString(numbers.getBytes());
                    // Html encode
                    numbers = htmlEncode(numbers);
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
                // Decode cipher
                cipher = htmlDecode(cipher);
                // Base64 decode
                byte[] cipherBytes = Base64.getDecoder().decode(cipher);
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
                    // Base64 encode
                    key = Base64.getEncoder().encodeToString(clientBytes);
                    // HTML Encode for transport
                    key = htmlEncode(key);

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
            // HTML decode from transport
            cipher = cipher.replace("%2B", "+");
            cipher = cipher.replace("%2F", "/");

            System.out.println("Cipher after url decode: " + cipher);

            // Get one time key for mobile number
            String oneTimeKey = requests.get(mobile);
            // Decode cipher from Base64
            byte[] decodedBytes = Base64.getDecoder().decode(cipher);

            // Decrypt bytes using ephemeral key
            char[] password = oneTimeKey.toCharArray();
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, 1000);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

            PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 1000);

            Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES/CBC/PKCS5Padding");
            pbeCipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
            byte[] decryptBytes = pbeCipher.doFinal(decodedBytes);

            // Get data from ciphertext
            String[] data = new String(decryptBytes).split("---");
            String phoneNum = data[0];
            byte[] nonceBytes = Base64.getDecoder().decode(data[1].getBytes());
            byte[] pubKeyBytes = Base64.getDecoder().decode(data[2].getBytes());
            PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubKeyBytes));

            // Open nonceBytes to get nonce data
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, pubKey);
            byte[] nonce = rsaCipher.doFinal(nonceBytes);

            // Does nonce match?
            if (new String(nonce).equals(phoneNum)) {
                // Remove from temp requests
                requests.remove(phoneNum);
                // Add to active clients
                clients.put(phoneNum, pubKey);
                // Modify nonce
                int nonceNum = Integer.parseInt(new String(nonce));
                nonceNum %= 2; // Mod the value
                // Encrypt nonce and public key of PKA using public key of client
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                baos.write(String.valueOf(nonceNum).getBytes()); // Modified Nonce
                baos.write("---".getBytes());
                baos.write(Base64.getEncoder().encode(publicKey.getEncoded())); // PKA pub key

                // Encrypt data with pub key of client (added security)
                rsaCipher.init(Cipher.ENCRYPT_MODE, pubKey);
                byte[] response = rsaCipher.doFinal(baos.toByteArray());
                // return data
                String responseBase64 = Base64.getEncoder().encodeToString(response);
                // HTML Encode for transport
                responseBase64 = responseBase64.replace("+", "%2B");
                responseBase64 = responseBase64.replace("/", "%2F");

                return responseBase64;
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
        } catch (IOException ex) {
            Logger.getLogger(ClientData.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    @Override
    public void requestOneTimeKey(String mobile, String email) {

        // Generate random one time password
        String password = generateOneTimePassword();
        // Add to requests mapping
        requests.put(mobile, password);
        
        // Gmail credentials
        final String USERNAME = "pkaserver2016@gmail.com";
        final String PASSWORD = "pkaserver,1234";
        
        // Sender's email ID needs to be mentioned
        String from = "no-reply@pkaserver.net";
        // Assuming you are sending email from gmail
        String host = "smtp.gmail.com";
        // Get system properties
        Properties properties = System.getProperties();
        // Setup mail server
        properties.put("mail.smtp.starttls.enable", "true");
        properties.put("mail.smtp.host", host);
        properties.put("mail.smtp.user", USERNAME);
        properties.put("mail.smtp.password", PASSWORD);
        properties.put("mail.smtp.port", "587");
        properties.put("mail.smtp.auth", "true");
        // Get the default Session object.
        Session session = Session.getDefaultInstance(properties);

        try {
            // Create a default MimeMessage object.
            MimeMessage message = new MimeMessage(session);
            // Set From: header field of the header.
            message.setFrom(new InternetAddress(from));
            // Set To: header field of the header.
            message.addRecipient(Message.RecipientType.TO, new InternetAddress(email));
            // Set Subject: header field
            message.setSubject("PKA Server Connection Request");
            // Now set the actual message
            message.setText("Your one time use key: " + password);

            // Send message
            Transport transport = session.getTransport("smtp");
            transport.connect(host, from, PASSWORD);
            transport.sendMessage(message, message.getRecipients(Message.RecipientType.TO));
            transport.close();
            
            System.out.println("Sent message successfully....");
        } catch (MessagingException mex) {
            mex.printStackTrace();
        }
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

    private String htmlDecode(String cipher) {
        // HTML decode from transport
        return cipher.replace("%2B", "+").replace("%2F", "/");
    }

    private String htmlEncode(String cipher) {
        // HTML encode for transport
        return cipher.replace("+", "%2B").replace("/", "%2F");
    }

    @Override
    public String getPkaPublicKey() {

        // Populate keys if not populated
        if (publicKey == null && privateKey == null) {
            generateKeys();
        }
        // Base 64 encode key
        String pubkey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        // HTML encode for transport
        pubkey = pubkey.replace("+", "%2B");
        pubkey = pubkey.replace("/", "%2F");
        // Return base64 & HTML encoded pka pub key
        return pubkey;
    }
}
