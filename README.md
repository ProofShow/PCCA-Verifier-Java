## PCCA Verifier Java
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Known Vulnerabilities](https://snyk.io//test/github/ProofShow/PCCAVerifierJava/badge.svg?targetFile=PCCAVerifier/pom.xml)](https://snyk.io//test/github/ProofShow/PCCAVerifierJava?targetFile=PCCAVerifier/pom.xml)
[![Build Status](https://travis-ci.com/ProofShow/PCCAVerifierJava.svg?branch=master)](https://travis-ci.com/ProofShow/PCCAVerifierJava)

PCCA Verifier Java is a java library for verifying Proof-Carrying Certificates™ issued by [PCCA](https://pcca.proof.show). The verification is done by

- Checking if the input certificate is correctly formatted according to [PCCA Certification Practice Statement](https://www.proof.show/pcca/PCCA_CPS.pdf);
- Checking if the input certificate, in particular, carries a DKIM Proof of CSR;
- Checking if the DKIM Proof of CSR can support the issuance of the input certificate according to the tracked DKIM keys of [PCCA Supported Email Services (PSES)](https://www.proof.show/pcca.html#pses).

For what it means by DKIM Proof of CSR, please refer to [PCCA Research Paper](https://www.proof.show/pcca/PCCA.pdf).

### Requirement
- JDK 1.8 or higher
- Maven

### How to install
To install this library to the local repository, run the following:

```
mvn install -pl PCCAVerifier
```

### How to use
To use this library, study the sample code in `PCCAVerifierExample` which can be build and run by the following:

```
mvn package
java -jar PCCAVerifierExample/target/PCCAVerifierExample.jar PATH_OF_CERT
```

### License
AGPL-3.0-or-later
