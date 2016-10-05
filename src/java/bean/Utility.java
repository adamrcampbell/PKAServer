package bean;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
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
    
    public static boolean isValidSender(PublicKey senderPublicKey, String encryptedMobile, 
            String senderMobile) {
        
        boolean isValid = false;
        
        // decode base 64
        byte[] decodedBytes = Utility.decodeFromBase64(encryptedMobile);
        // Decrypt for mobile number
        String decryptedMobile = new String(decryptRSA(senderPublicKey, decodedBytes));
        // Compare  mobile numbers
        if (decryptedMobile.equals(senderMobile)) {
            isValid = true;
        }
        
        return isValid;
    }
    
    /**
     * Function extracting modulus and exponent from a given PublicKey value 
     * 
     * @param pub PublicKey value
     * @return String array containing the modulus in [0] and exponent in [1]
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    static public String[] getPubKeyVal(PublicKey pub) throws NoSuchAlgorithmException, InvalidKeySpecException{        
        byte[] pubBytes = pub.getEncoded();
        KeyFactory kf = KeyFactory.getInstance("RSA");
        
        //Recover public key
        PublicKey rePub = kf.generatePublic(new X509EncodedKeySpec(pubBytes));
        String pubString = rePub.toString();
        
        //Extract modulus value from the public key
        String[] parts = pubString.split("public");
        String[] modString = parts[1].split("modulus: ");
        String pubKeyMod = modString[1].replaceAll("\\s", "");
        String[] expString = parts[2].split("exponent: ");
        String pubKeyExp = expString[1].replaceAll("\\s", "");
        
        String[] pubKeyModExp = new String[] {pubKeyMod, pubKeyExp};
        return (pubKeyModExp);
    }
}
