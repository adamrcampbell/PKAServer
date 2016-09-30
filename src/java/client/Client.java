package client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.Base64;
import java.util.Set;
import javax.crypto.spec.PBEParameterSpec;

public class Client {

    private String phoneNum;
    private String oneTimeKey;
    private SecretKey ephemeralKey;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private PublicKey pkaPubKey;
    
    private final byte[] salt = {-84, 40, -10, -53, -80, 90, -57, 125};

    public Client(String phoneNum, String oneTimeKey) {
        this.phoneNum = phoneNum;
        this.oneTimeKey = oneTimeKey;
    }

    public static void main(String[] args) {

        // Received privately from PKA Server
        String oneTimeKey = "apple123";

        // Set up client
        Client client = new Client("0212556332", oneTimeKey);
        // Generate ephemeral key
        client.generateEphemeral(client.oneTimeKey);
        // Create pub/pri RSA keys
        client.generateKeys();
        // Encrypt details
        byte[] cipherBytes = client.encryptDetails();
        
        String bytesEncoded = Base64.getEncoder().encodeToString(cipherBytes);
        System.out.println("Length: " + bytesEncoded.length());                   
        
        // HTML Encode for transport
        bytesEncoded = bytesEncoded.replace("+", "%2B");
        bytesEncoded = bytesEncoded.replace("/", "%2F");
        
        System.out.println("Cipher: " + bytesEncoded);
        System.out.println("Length: " + bytesEncoded.length());
    }

    private void generateEphemeral(String password) {

        SecretKey key = null;

        try {
            char[] passwordChar = password.toCharArray();
            PBEKeySpec pbeSpec = new PBEKeySpec(passwordChar, salt, 1000);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEwithMD5andDES");
            key = keyFactory.generateSecret(pbeSpec);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        ephemeralKey = key;
    }

    private void generateKeys() {

        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair keyPair = kpg.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
            
            System.out.println("PubKey: " + publicKey);
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private byte[] encryptDetails() {

        try {
            // Prep cipher
            Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES/CBC/PKCS5Padding");
            pbeCipher.init(ENCRYPT_MODE, ephemeralKey, new PBEParameterSpec(salt, 1000));

            // Encrypt nonce with pub key of pka (added security)
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, pkaPubKey);
            byte[] nonceBytes = rsaCipher.doFinal(phoneNum.getBytes());
            
            // Package data
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(phoneNum.getBytes());
            baos.write("---".getBytes());
            baos.write(Base64.getEncoder().encode(nonceBytes)); // encrypted with private RSA
            baos.write("---".getBytes());
            baos.write(Base64.getEncoder().encode(publicKey.getEncoded()));

            // Encrypt and return
            byte[] cipherBytes = pbeCipher.doFinal(baos.toByteArray());
            return cipherBytes;
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }
}
