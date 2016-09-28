package bean;

import java.util.Base64;

/**
 *
 * @author Adam
 */
public class Utility {

    public static byte[] decodeFromBase64(String cipher) {
        // HTML decode from transport
        cipher = cipher.replace("%2B", "+").replace("%2F", "/");
        // Base64 decode
        return Base64.getDecoder().decode(cipher);
    }

    public static String encodeToBase64(byte[] data) {
        // Encode bytes into base64
        String encodedData = Base64.getEncoder().encodeToString(data);
        // HTML encode for transport
        return encodedData.replace("+", "%2B").replace("/", "%2F");
    }
}
