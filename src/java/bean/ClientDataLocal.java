
package bean;

import javax.ejb.Local;

@Local
public interface ClientDataLocal {

    String getAllNumbers(String mobile, String cipher);

    String getPublicKey(String mobile, String cipher);

    String joinServer(String mobile, String base64);

    void requestOneTimeKey(String mobile, String email);

    String getPkaPublicKey();
}
