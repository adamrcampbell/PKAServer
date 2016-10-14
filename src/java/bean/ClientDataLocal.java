
package bean;

import javax.ejb.Local;

@Local
public interface ClientDataLocal {

    String getAllNumbers(String mobile, String validation);

    String getPublicKey(String mobile, String request);

    String joinServer(String mobile, String request);

    String requestOneTimeKey(String mobile);

    String getPkaPublicKey();
}
