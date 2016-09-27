
package rest;

import bean.ClientDataLocal;
import javax.ejb.EJB;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;

@Path("pka")
public class KeyResource {
    
    @EJB
    private ClientDataLocal clientBean;
    
    @Path("request/{mobile}/{email}")
    @POST
    @Produces("text/plain")
    public void requestOneTimeKey(@PathParam("mobile") String mobile, @PathParam("email") String email) {
        clientBean.requestOneTimeKey(mobile, email);
    }
    
    @Path("join/{mobile}/{base64}")
    @POST
    @Produces("text/plain")
    public String joinServer(@PathParam("mobile") String mobile, @PathParam("base64") String base64) {
        return clientBean.joinServer(mobile, base64);
    }
    
    @Path("numbers/{mobile}/{cipher}")
    @POST
    @Produces("text/plain")
    public String requestNumbers(@PathParam("mobile") String mobile, @PathParam("cipher") String cipher) {
        return "";
    }
    
    @Path("publickey/{mobile}/{cipher}")
    @POST
    @Produces("text/plain")
    public String requestPublicKey(@PathParam("mobile") String mobile, @PathParam("cipher") String cipher) {
        return "";
    }
    
    @Path("pkakey")
    @POST
    @Produces("text/plain")
    public String requestPkaPubKey() {
        return clientBean.getPkaPublicKey();
    }
}