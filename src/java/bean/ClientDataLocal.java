
package bean;

import javax.ejb.Local;

@Local
public interface ClientDataLocal {

    String getAllNumbers(String mobile, String cipher, String validation);

    String getPublicKey(String mobile, String cipher, String validation);

    String joinServer(String mobile, String base64, String validation);

    String requestOneTimeKey(String mobile);

    String getPkaPublicKey();
}
