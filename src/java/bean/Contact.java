
package bean;

import java.security.PublicKey;
import javax.crypto.SecretKey;

public class Contact {
    
    private SecretKey ephemeral;
    private PublicKey publicKey;
    
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
}
