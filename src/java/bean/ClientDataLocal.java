
package bean;

import javax.ejb.Local;

@Local
public interface ClientDataLocal {

    String getAllNumbers(String mobile, String request);

    String getPublicKey(String mobile, String request);

    String joinServer(String mobile, String request);

    String requestOneTimeKey(String mobile);

    String getPkaPublicKey();

    String requestImageKey(String mobile, String request);

    boolean processUpload(String mobile, String data);

    String processDownload(String mobile, String request);

    String getFileNames(String mobile, String request);
}
