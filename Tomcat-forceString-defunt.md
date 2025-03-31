# Analysis: Removal of `forceString` from `org.apache.naming.factory.BeanFactory` in Apache Tomcat

This document investigates the version of Apache Tomcat in which the `forceString` functionality was removed or disabled from the `org.apache.naming.factory.BeanFactory` class, based on an analysis of the Apache Tomcat GitHub repository, changelogs, bug tracker entries, and source code.

## Background

The `forceString` attribute in `org.apache.naming.factory.BeanFactory` allowed users to specify custom setter methods for bean properties, enabling string values to be coerced into other types. This feature, while flexible, posed security risks, particularly in the context of JNDI injection vulnerabilities (e.g., similar to Log4j exploits). As a result, it was targeted for removal or mitigation.

## Investigation

The analysis involved:
1. Reviewing the Apache Tomcat GitHub repository for changes to `BeanFactory.java`.
2. Examining the official Tomcat changelogs for version-specific details.
3. Consulting Bug 65736 on the Apache Bugzilla for context on the change.
4. Comparing code across Tomcat releases to confirm the removal point.

### Key Findings

- **Bug 65736**: Raised on May 8, 2022, with initial discussion on December 10, 2021, this bug proposed hardening `BeanFactory` against JNDI injection by addressing `forceString`.
- **Tomcat 8.5.82**: Released on August 22, 2023, this version disabled `forceString` functionality:
  - Changelog entry: _"Disable the forceString option for the JNDI BeanFactory and replace it with an automatic search for an alternative setter with the same name that accepts a String. This is a security hardening measure."_ (Bug 65736)
  - Code change: In `BeanFactory.java`, `forceString` is checked but triggers a warning and is ignored, replaced by automatic setter detection.
- **Later Versions**: Up to Tomcat 10.1.36 (February 13, 2025), the `forceString` reference remains in the code with a warning but has no functional impact.

### Conclusion

The `forceString` functionality was **effectively removed (disabled)** in **Apache Tomcat 8.5.82** (August 22, 2023). While the attribute’s mention persists in the source code (with a warning), its operational effect was eliminated, replaced by an automatic setter search. No full removal (i.e., deletion of the check) occurred up to Tomcat 10.1.36.

## References

- **Apache Tomcat GitHub Repository**:  
  [github.com/apache/tomcat](https://github.com/apache/tomcat)  
  - File: `java/org/apache/naming/factory/BeanFactory.java`
- **Tomcat 8.5.82 Changelog**:  
  [tomcat.apache.org/tomcat-8.5-doc/changelog.html#8.5.82](https://tomcat.apache.org/tomcat-8.5-doc/changelog.html)  
  - See Bug 65736 entry under “Catalina.”
- **Bug 65736 on Apache Bugzilla**:  
  [bz.apache.org/bugzilla/show_bug.cgi?id=65736](https://bz.apache.org/bugzilla/show_bug.cgi?id=65736)  
  - Discussion and resolution details.
- **Fossies Archive for Tomcat 10.1.36**:  
  [fossies.org/linux/www/apache-tomcat-10.1.36-src.tar.gz/apache-tomcat-10.1.36-src/java/org/apache/naming/factory/BeanFactory.java](https://fossies.org/linux/www/apache-tomcat-10.1.36-src.tar.gz/apache-tomcat-10.1.36-src/java/org/apache/naming/factory/BeanFactory.java)  
  - Confirms persistence of the warning in later versions.
- **General Tomcat Changelog**:  
  [tomcat.apache.org/tomcat-8.5-doc/changelog.html](https://tomcat.apache.org/tomcat-8.5-doc/changelog.html)  
  - Navigate to other versions (e.g., 9.0.x, 10.1.x) for comparison.

## Notes

- The exact commit for 8.5.82 can be found in the GitHub repo by checking the `8.5.82` tag or commits around August 2023.
- This analysis was conducted as of March 31, 2025, with knowledge of Tomcat releases up to 10.1.36.