package bean;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author Adam
 */
public class Utility {

    // Agreed salt between client and PKA
    public static final byte[] IV = {-84, 40, -10, -53, -80, 90, -57, 125, -84, 40, -10, -53, -80, 90, -57, 125};
    
    public static byte[] decodeFromBase64(String cipher) {
        // HTML decode from transport
        cipher = cipher.replace("%2B", "+").replace("%2F", "/").replace("%3D", "=").replace("%7C", "|");
        // Base64 decode
        return Base64.getDecoder().decode(cipher);
    }

    public static String encodeToBase64(byte[] data) {
        // Encode bytes into base64
        String encodedData = Base64.getEncoder().encodeToString(data);
        // HTML encode for transport
        return encodedData.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D").replace("|", "%7C");
    }
    
    public static byte[] encryptRSA(Key key, byte[] data) {

        byte[] encrypted = null;

        try {
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, key);
            encrypted = rsaCipher.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            System.out.println("Unable to encrypt via encryptRSA");
        }

        return encrypted;
    }

    public static byte[] decryptRSA(Key key, byte[] data) {

        byte[] decrypted = null;

        try {
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, key);
            decrypted = rsaCipher.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            System.out.println("Unable to decrypt via decryptRSA");
        }

        return decrypted;
    }
    
    public static byte[] decryptAES(SecretKey key, byte[] data) {
            
        try {
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec initVector = new IvParameterSpec(IV);
            // initialize cipher for decryption
            aesCipher.init(Cipher.DECRYPT_MODE, key, initVector);
            // Decrypt request and return
            return aesCipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            System.out.println("Unable to decrypt AES");
        }
        
        return null;
    }
    
    public static byte[] encryptAES(SecretKey key, byte[] data) {
                
        try {
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec initVector = new IvParameterSpec(IV);
            // initialize cipher for decryption
            aesCipher.init(Cipher.ENCRYPT_MODE, key, initVector);
            // Encrypt request and return
            return aesCipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            System.out.println("Unable to encrypt AES");
        }
        
        return null;
    }
    
    public static String doubleEncryptData(byte[] data, 
            Key recipientKey, Key pkaKey) {
        
        ArrayList<byte[]> chunks = new ArrayList<>();

        // Segment data to encrypt into 100 byte chunks (or remainder)
        for(int i = 0; i < data.length;) {

            int difference = data.length - i;

            if(difference >= 100) {
                byte[] chunk = new byte[100];

                for(int x = 0; x < 100; x++)
                    chunk[x] = data[i++];

                chunks.add(chunk);
            }
            else {
                byte[] chunk = new byte[difference];

                for(int x = 0; x < difference; x++)
                    chunk[x] = data[i++];

                chunks.add(chunk);
            }
        }

        byte[] encryptedChunk = new byte[chunks.size() * 256]; 
        int counter = 0;

        // Encrypt chunks
        for(int i = 0; i < chunks.size(); i++) {
            try {
                // Get chunk i
                byte[] chunk = chunks.get(i);
                // Encrypt inner layer with pka private key
                Cipher rsaCipher = Cipher.getInstance("RSA/ECB/NoPadding");
                rsaCipher.init(Cipher.ENCRYPT_MODE, pkaKey);
                byte[] inner = rsaCipher.doFinal(chunk);
                // Encrypt outer layer with recipient public key
                Cipher rsaCipher2 = Cipher.getInstance("RSA/ECB/NoPadding");
                rsaCipher2.init(Cipher.ENCRYPT_MODE, recipientKey);
                byte[] outer = rsaCipher2.doFinal(inner);
                
                for(int x = 0; x < outer.length; x++)
                    encryptedChunk[counter++] = outer[x];
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException ex) {
                System.out.println("Unable to encrypt data package for transport");
            }
        }
        
        // Build up contents for transport response of HTTP post
        // "actual bytes length ||| transportation bytes length ||| byte data"
        StringBuilder sb = new StringBuilder();
        sb.append(data.length).append("|||");
        sb.append(encryptedChunk.length).append("|||");
        sb.append(Utility.encodeToBase64(encryptedChunk));
        
        return sb.toString();
    }
    
    public static byte[] doubleDecryptData(String data, Key pkaKey,
            Key senderKey) {
        
        byte[] decodedData = Utility.decodeFromBase64(data);
            String[] dataSplit = new String(decodedData).split("\\|\\|\\|");
        int actualDataLength = Integer.parseInt(dataSplit[0]);
        int paddedDataLength = Integer.parseInt(dataSplit[1]);
        byte[] decoded = Utility.decodeFromBase64(dataSplit[2]);
        
        ArrayList<byte[]> encryptedChunks = new ArrayList<>();
        
        // Break decoded data into padded chunks
        for(int i = 0; i < paddedDataLength / 256; i++) {
            byte[] chunk = new byte[256];
            
            int upper = (256 * i) + 256;
            
            for(int y = upper - 256, counter = 0; y < upper; y++)
                chunk[counter++] = decoded[y];
            
            encryptedChunks.add(chunk);
        }
        
        // Decrypt chunks
        for(int i = 0; i < encryptedChunks.size(); i++) {
            try {
                // Get chunk
                byte[] chunk = encryptedChunks.get(i);
                // Decrypt outer layer with pka private key
                Cipher rsaCipher = Cipher.getInstance("RSA/ECB/NoPadding");
                rsaCipher.init(Cipher.DECRYPT_MODE, pkaKey);
                byte[] outer = rsaCipher.doFinal(chunk);
                // Decrypt inner layer with recipient public key
                Cipher rsaCipher2 = Cipher.getInstance("RSA/ECB/NoPadding");
                rsaCipher2.init(Cipher.DECRYPT_MODE, senderKey);
                byte[] inner = rsaCipher2.doFinal(outer);
                
                int dataLength = (actualDataLength >= 100) ? 100 : actualDataLength;
                byte[] actualData = new byte[dataLength];
                
                // Get actual data from chunk
                for(int x = inner.length - dataLength, counter = 0; x < inner.length;)
                    actualData[counter++] = inner[x++];
                
                // Replace chunk
                encryptedChunks.set(i, actualData);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                System.out.println("Unable to decrypt data package from transport");
            }
        }
            
        // Concatenate chunks into one byte array
        byte[] dataChunk = new byte[actualDataLength];
        int counter = 0;
        
        for(byte[] chunk : encryptedChunks) {
            for(byte b : chunk)
                dataChunk[counter++] = b;
        }
        
        return dataChunk;
    }
}
