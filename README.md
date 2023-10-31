# hl7-fhir-udap-client

## Overview

This nodejs library is part of a four-repository collection for a full [UDAP](https://www.udap.org/) implementation. The implementation adheres to published Version 1.0 of the [HL7 UDAP Security Implementation Guide](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/). This library implements a udapClient class. The constructor takes in the following attributes:
- communityKeystoreFilename: The PCKS#12 file (.p12). Contains public and private keys for trust community.
- communityKeystorePassword: The password to the PCKS#12 file.
- trustAnchorFilename: Trust community trust anchor in PEM format.
- clientId: Client id for the associated UDAP server this instance is connecting to. Optional if client has not registered with server yet pass in "".
- serverBaseUrl: Base FHIR url for the server this client instance is connecting to.

The following are defined in Defined in [B2B Authorizaion Extension Object](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/b2b.html#b2b-authorization-extension-object):

- organizationId: Unique identifier for the ogranization represented by this udap client instance
- organizationName: String representation of the organization represented by this udap client instance
- purposeOfUse: The purpose for which the data requested will be used

The client class has methods to handle UDAP Trusted Dynamic Client Registration, UDAP Authorization Code Flow, and UDAP Client Credentials Flow, as well as caching and validating UDAP metadata.

## Usage

To see example code, you can browse the [hl7-fhir-udap-client-ui](https://github.com/Evernorth/hl7-fhir-udap-client-ui#readme) and [hl7-fhir-udap-server](https://github.com/Evernorth/hl7-fhir-udap-server#readme) repositories.

## Installation

The repositories are currently set up for local installation. Placing all four repositories under the same parent folder will allow the package.json local file references to be resolved accurately. This repository will eventually be an npm package.

## Getting Help

If you have questions, concerns, bug reports, etc.,  file an issue in this repository's Issue Tracker.

## Getting Involved

See the [CONTRIBUTING.md](CONTRIBUTING.md) file for info on how to get involved.

## License

The hl7-fhir-udap-client is Open Source Software released under the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0.html).

## Original Contributors

The hl7-fhir-udap-client was originally developed as a collaborative effort between [Evernorth](https://www.evernorth.com/) and [OKTA](https://www.okta.com/). We would like to recognize the following people for their initial contributions to the project: 
 - Tom Loomis, Evernorth
 - Dan Cinnamon, OKTA