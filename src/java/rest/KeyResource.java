
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
    
    @Path("request/{mobile}")
    @POST
    @Produces("text/plain")
    public String requestOneTimeKey(@PathParam("mobile") String mobile) {
        return clientBean.requestOneTimeKey(mobile);
    }
    
    @Path("join/{mobile}/{base64}")
    @POST
    @Produces("text/plain")
    public String joinServer(@PathParam("mobile") String mobile, @PathParam("base64") String base64) {
        return clientBean.joinServer(mobile, base64);
    }
    
    @Path("numbers/{mobile}/{base64}")
    @POST
    @Produces("text/plain")
    public String requestNumbers(@PathParam("mobile") String mobile, @PathParam("base64") String base64) {
        return clientBean.getAllNumbers(mobile, base64);
    }
    
    @Path("publickey/{mobile}/{base64}")
    @POST
    @Produces("text/plain")
    public String requestPublicKey(@PathParam("mobile") String mobile, @PathParam("base64") String base64) {
        return clientBean.getPublicKey(mobile, base64);
    }
    
    @Path("pkakey")
    @POST
    @Produces("text/plain")
    public String requestPkaPubKey() {
        return clientBean.getPkaPublicKey();
    }
}