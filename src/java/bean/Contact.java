
package bean;

import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Contact {
    
    private SecretKey ephemeral;
    private PublicKey publicKey;
    private SecretKey fileKey;
    
    public Contact(SecretKey ephemeral, PublicKey publicKey) {
        this.ephemeral = ephemeral;
        this.publicKey = publicKey;
    }

    public SecretKey getEphemeral() {
        return ephemeral;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
    
    public SecretKey getFileKey() {
        return fileKey;
    }
    
    public SecretKey requestFileKey() {
        
        // Produce key
        byte[] aesBytes = new byte[16];
        new SecureRandom().nextBytes(aesBytes);
        SecretKey secretKey = new SecretKeySpec(aesBytes, "AES");
        // Store key
        fileKey = secretKey;
        // Return key
        return fileKey;
    }
}
