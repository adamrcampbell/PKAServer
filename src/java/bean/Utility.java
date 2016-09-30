package bean;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author Adam
 */
public class Utility {

    public static byte[] decodeFromBase64(String cipher) {
        // HTML decode from transport
        cipher = cipher.replace("%2B", "+").replace("%2F", "/").replace("%3D", "=");
        // Base64 decode
        return Base64.getDecoder().decode(cipher);
    }

    public static String encodeToBase64(byte[] data) {
        // Encode bytes into base64
        String encodedData = Base64.getEncoder().encodeToString(data);
        // HTML encode for transport
        return encodedData.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D");
    }
    
    public static byte[] encryptRSA(Key key, byte[] data) {

        byte[] encrypted = null;

        try {
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, key);
            encrypted = rsaCipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
        } catch (InvalidKeyException e) {
        } catch (NoSuchPaddingException e) {
        } catch (BadPaddingException e) {
        } catch (IllegalBlockSizeException e) {
        }

        return encrypted;
    }

    public static byte[] decryptRSA(Key key, byte[] data) {

        byte[] decrypted = null;

        try {
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, key);
            decrypted = rsaCipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
        } catch (InvalidKeyException e) {
        } catch (NoSuchPaddingException e) {
        } catch (BadPaddingException e) {
        } catch (IllegalBlockSizeException e) {
        }

        return decrypted;
    }
}
