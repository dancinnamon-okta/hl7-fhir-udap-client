'use strict'
const udapCommon = require('udap-common')
const fs = require('fs')
const axios = require('axios')
const querystring = require('querystring')
const { v4: uuidv4 } = require('uuid')
const udapClientError = require('./udap-client-error')

class udapClient {
    constructor(communityKeystoreFilename, communityKeystorePassword, trustAnchorFilename, clientId, serverBaseUrl, organizationId, organizationName, purposeOfUse) {
        this.communityKeystoreFilename = communityKeystoreFilename
        this.trustAnchorFilename = trustAnchorFilename
        this.communityKeystore = udapCommon.parsePKCS12(communityKeystoreFilename, communityKeystorePassword)
        this.communityKeypair = this.communityKeystore[0]
        //We're assuming we're using the first certificate found in the store.
        this.communityCert = this.communityKeypair.certChain[0]
        this.trustAnchorObject = udapCommon.parseTrustAnchorPEM(trustAnchorFilename)
        this.clientId = clientId
        this.serverBaseUrl = serverBaseUrl
        this.udapWellknownUrl = serverBaseUrl + '/.well-known/udap'
        this.organizationId = organizationId
        this.organizationName = organizationName
        this.purposeOfUse = purposeOfUse
        this.udapWellKnownMetadata = null
        this.signedMetadata = null
    }
    //Full Client UDAP Trusted Dynamic Client Registration Flow
    // 1. Check for support in metadata
    // 2. Validate Signed metadata of server
    // 3. UDAP Trusted DCR
    
    /*
    Registration config:
    client_name: registrationClaims.client_name, //Let's take this in on registration
    grant_types: registrationClaims.grant_types, //Let's take this in on registration //lets take this on on registration and/or token request
    response_types: registrationClaims.response_types, //Let's take this in on registration and/or token request
    contacts: registrationClaims.contacts, //Let's take this in on registration
    logouri: registrationClaims.logouri, //Let's take this in on registration
    scope: registrationClaims.scopes //Let's take this in on registration and/or token request
    san: subject alternative name  
    */
    async udapDynamicClientRegistration(registrationConfiguration) {
        console.log("Looking up additional server info from:" + this.udapWellknownUrl)
        try {
            await this.getAndValidateUdapMetadata(this.udapWellknownUrl)
            var registerUrl = this.signedMetadata.registration_endpoint
            //Make sure to use algorithim the server supports
            var signingAlg = this.udapWellKnownMetadata.registration_endpoint_jwt_signing_alg_values_supported[0]
            var signedJwt = this.createUdapSignedSoftwareStatement(registerUrl, registrationConfiguration,signingAlg)
            console.log(signedJwt)
            var softwareStatement = {
                "software_statement": signedJwt,
                "udap": "1"
            }
            var dcrResponse = await this.postUdapRequest(softwareStatement, registerUrl,'application/json')
            console.log(dcrResponse)
            return dcrResponse
        }
        catch (e) {
            console.error("Error registering client:")
            console.error(e.message)
            throw new udapClientError(e)
        }
    }

    //Method for initializing the authorization code flow.
    async udapAuthorizeRequest(upstreamIdpUrl, scope, redirectUri) {
        const state = uuidv4()
        var authorizeParameters = {
            "client_id": this.clientId,
            "response_type": "code",
            "state": state,
            "redirect_uri": redirectUri
        }
        //Tiered-Oauth if appropriate.
        //TODO:  Check for server support of Tiered Oauth
        if (upstreamIdpUrl) {
            console.log("Upstream IDP URL passed in adding udap scope for tiered-oauth")
            authorizeParameters.idp = upstreamIdpUrl
            authorizeParameters.scope = (scope + " udap")
        }
        else {
            authorizeParameters.scope = scope
        }
        try {
            await this.getAndValidateUdapMetadata(this.udapWellknownUrl)
            const authorizeUrl = this.signedMetadata.authorization_endpoint
            const output = {
                "authorizeUrl": authorizeUrl + "?" + querystring.stringify(authorizeParameters),
                "state": state
            }
            return output
        }
        catch (e) {
            console.error("Error in udapAuthorizeRequest:")
            console.error(e.message)
            throw new udapClientError(e)
        }
    }

    //Method for completing the client credential flow.
    async udapTokenRequestClientCredentials(scope) {
        try {
            await this.getAndValidateUdapMetadata(this.udapWellknownUrl)
            var tokenUrl = this.signedMetadata.token_endpoint
            var signingAlg = this.udapWellKnownMetadata.token_endpoint_auth_signing_alg_values_supported[0]
            var signedJwt = this.createUdapSignedAuthenticationToken(tokenUrl,signingAlg)
            var tokenRequest = {
                'grant_type': 'client_credentials',
                'scope': scope,
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion': signedJwt,
                'udap': 1
            }
            //var tokenResponse = await UdapClient.postUdapSignedJwt(tokenRequest,tokenUrl)
            //We can put this back into a method later- this needs to be NOT JSON- but url encoded.
            console.log("Ready to get token from the authz server at endpoint: " + tokenUrl)
            console.log(querystring.stringify(tokenRequest))
            try {
                const tokenResponse = await this.postUdapRequest(tokenRequest,tokenUrl,'application/x-www-form-urlencoded')
                return tokenResponse
            }
            catch (e) {
                console.error("Error during Token Request ClientCredentials:")
                console.error(e.message)
                throw new udapClientError(e)
            }
        }
        catch (e) {
            console.error("Error in udapTokenRequestClientCredentials:")
            console.error(e.message)
            throw new udapClientError(e)
        }
    }

    //Method for completing the authorization code flow.
    async udapTokenRequestAuthCode(authCode, redirectUri) {
        try {
            await this.getAndValidateUdapMetadata(this.udapWellknownUrl)
            var tokenUrl = this.signedMetadata.token_endpoint
            var signingAlg = this.udapWellKnownMetadata.token_endpoint_auth_signing_alg_values_supported[0]
            var signedJwt = this.createUdapSignedAuthenticationToken(tokenUrl,signingAlg)
            var tokenRequest = {
                'grant_type': 'authorization_code',
                'redirect_uri': redirectUri,
                'code': authCode,
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion': signedJwt,
                'udap': 1
            }
            //We can put this back into a method later- this needs to be NOT JSON- but url encoded.
            console.log("Ready to get token from the authz server at endpoint: " + tokenUrl)
            console.log(querystring.stringify(tokenRequest))
            try {
                const tokenResponse = await this.postUdapRequest(tokenRequest,tokenUrl,'application/x-www-form-urlencoded')
                console.log(tokenResponse)
                return tokenResponse
            }
            catch (e) {
                console.error("Error during token request AuthCode:")
                console.error(e)
                throw new udapClientError(e)
            }
        }
        catch (e) {
            console.error("Error in udapTokenRequestAuthCode:")
            console.error(e)
            throw new udapClientError(e)
        }
    }

    //Method gets UDAP wellknown meta data from passed in url.
    // Checks to see if meta data has already been retrieved first.
    // If there are no errors instance property signedMetadata contains the verified and validated signed_metadata jwt
    //Validates .wellknown-udap and signed_metadata version STU 1 of HL7 security guide:
    // http://hl7.org/fhir/us/udap-security/STU1/
    async getAndValidateUdapMetadata(url) {
        if (this.signedMetadata == null) {
            try {
                const udapMetaResponse = await axios.request({
                    'url': url,
                    'method': 'get',
                    'headers': { 'Content-Type': 'application/fhir+json' },
                })
                console.log("Return from meta")
                console.log(udapMetaResponse)
                if (udapMetaResponse.status == 200) {
                    var udapWellKnownResponse = udapMetaResponse.data
                    await this.validateUdapWellKnown(udapWellKnownResponse)
                }
            }
            catch (e) {
                console.error("Error getting meta data:")
                console.error(e)
                throw new udapClientError(e)
            }
        }
    }

    async postUdapRequest(request, postUrl,contentType) {
        const postResponse = await axios.request({
            'url': postUrl,
            'method': 'post',
            'headers': { 'Content-Type': contentType },
            'data': request
        })
        return postResponse
    }

    async validateUdapWellKnown(udapWellKnownJson) {
        udapClientError.code = "udap_wellknown_paramter_error"
        var errorMessages = [];
        if (!udapWellKnownJson.hasOwnProperty("udap_versions_supported") || udapWellKnownJson.udap_versions_supported.length == 0) {
            errorMessages.push("Missing or invalid udap_versions_supported parameter")
        }
        if (!udapWellKnownJson.hasOwnProperty("udap_profiles_supported") || udapWellKnownJson.udap_profiles_supported.length < 1 ||
            (udapWellKnownJson.udap_profiles_supported.includes("udap_dcr") == null || udapWellKnownJson.udap_profiles_supported.includes("udap_authn") == null)) {
            errorMessages.push("Missing or invalid udap_profiles_supported parameter at least udap_dcr and udap_authn must be supported")
        }
        if (!udapWellKnownJson.hasOwnProperty("udap_authorization_extensions_supported")) {
            errorMessages.push("Missing udap_authorization_extensions_supported parameter")
        }
        if (!udapWellKnownJson.hasOwnProperty("udap_authorization_extensions_required") &&
            ((udapWellKnownJson.udap_authorization_extensions_supported.length > 0) &&
                (!udapWellKnownJson.hasOwnProperty("udap_authorization_extensions_required") || udapWellKnownJson.udap_authorization_extensions_required.length == 0))) {
            errorMessages.push("Missing or Invalid udap_authorization_extensions_required parameter")
        }
        if (!udapWellKnownJson.hasOwnProperty("udap_certifications_supported")) {
            errorMessages.push("Missing udap_certifications_supported parameter")
        }
        if (!udapWellKnownJson.hasOwnProperty("udap_certifications_required") ||
            ((udapWellKnownJson.udap_certifications_supported.length > 0) &&
                (!udapWellKnownJson.hasOwnProperty("udap_certifications_required") || udapWellKnownJson.udap_certifications_required.length == 0))) {
            errorMessages.push("Missing or Invalid udap_certifications_required parameter")
        }
        if (!udapWellKnownJson.hasOwnProperty("grant_types_supported") || udapWellKnownJson.grant_types_supported.length == 0) {
            errorMessages.push("Missing or invalid grant_types_supported parameter")
        }
        if (udapWellKnownJson.hasOwnProperty("grant_types_supported") && !udapWellKnownJson.grant_types_supported.length > 0 &&
            (udapWellKnownJson.grant_types_supported.includes("client_credentials")  &&
                !udapWellKnownJson.udapWellKnownJson.udap_profiles_suppoted.includes("udap_authz")) ||
            (udapWellKnownJson.grant_types_supported.includes("authorization_code") && !udapWellKnownJson.grant_types_supported.includes("refresh_token"))) {
            errorMessages.push("Invalid grant_types_supported and udap_profiles_supported parameters")
        }
        if (!udapWellKnownJson.hasOwnProperty("authorization_endpoint") && !udapWellKnownJson.grant_types_supported.includes("authorization_code")) {
            errorMessages.push("Missing or invalid authorization_endpoint parameter")
        }
        if (!udapWellKnownJson.hasOwnProperty("token_endpoint")) {
            errorMessages.push("Missing or invalid token_endpoint parameter")
        }
        if (!udapWellKnownJson.hasOwnProperty("token_endpoint_auth_methods_supported") || udapWellKnownJson.token_endpoint_auth_methods_supported.length == 0 ||
            !udapWellKnownJson.token_endpoint_auth_methods_supported.includes("private_key_jwt")) {
            errorMessages.push("Missing or invalid token_endpoint_auth_methods_supported parameter")
        }
        if (!udapWellKnownJson.hasOwnProperty("token_endpoint_auth_signing_alg_values_supported") || udapWellKnownJson.token_endpoint_auth_signing_alg_values_supported.length == 0) {
            errorMessages.push("Missing or invalid token_endpoint_auth_signing_alg_values_supported parameter.")
        }
        if (!udapWellKnownJson.hasOwnProperty("registration_endpoint")) {
            errorMessages.push("Missing or invalid registration_endpoint parameter")
        }
        if (!udapWellKnownJson.hasOwnProperty("registration_endpoint_jwt_signing_alg_values_supported") || udapWellKnownJson.registration_endpoint_jwt_signing_alg_values_supported.length == 0) {
            errorMessages.push("Missing or invalid registration_endpoint_jwt_signing_alg_values_supported parameter.")
        }
        if (udapWellKnownJson.hasOwnProperty("signed_metadata")) {
            var udapsignedMetadata = await this.validatesignedMetadata(udapWellKnownJson, errorMessages)
        }
        if (errorMessages.length > 0) {
            var message = errorMessages.join("\r\n")
            var error = new udapClientError(message)
            throw error
        }
        this.udapWellKnownMetadata = udapWellKnownJson
        this.signedMetadata = udapsignedMetadata
    }

    async validatesignedMetadata(udapWellKnownJson, errorMessages) {
        var signedMetadata = udapWellKnownJson.signed_metadata
        var verifiedJwtAndCertObject
        try {
            verifiedJwtAndCertObject = await udapCommon.verifyUdapJwtCommon(signedMetadata, this.trustAnchorObject)
        }
        catch (e) {
            errorMessages.push("Signed meta data jwt can not be verified: " + e.message)
        }
        var verifiedJwt = verifiedJwtAndCertObject.verifiedJwt.body
        if (!verifiedJwt.hasOwnProperty("iss") || !udapCommon.validateSanInCert(verifiedJwt.iss, verifiedJwtAndCertObject.verifiedJwtCertificate) ||
            verifiedJwt.iss != this.serverBaseUrl) {
            errorMessages.push("Missing or invalid iss parameter in signed_metadata.")
        }
        else if (!verifiedJwt.hasOwnProperty("sub") || verifiedJwt.sub != verifiedJwt.iss) {
            errorMessages.push("Missing or invalid sub parameter in signed_metadata.")
        }
        var now = new Date()
        var oneYearForward = new Date()
        oneYearForward.setFullYear(oneYearForward.getFullYear() + 1)
        console.log("IAT: " + (verifiedJwt.iat * 1000) + " Exp: " + (verifiedJwt.exp * 1000) + " Current Date: " + now.getTime() + " 1 year Forward: " + oneYearForward.getTime())
        if (!verifiedJwt.hasOwnProperty('iat') || verifiedJwt.iat == "" || (verifiedJwt.iat * 1000) >= now.getTime()) {
            errorMessages.push("Missing or invalid sub parameter in signed_metadata.")
        }
        if (!verifiedJwt.hasOwnProperty('exp') || verifiedJwt.exp == "" || (verifiedJwt.exp * 1000 <= now.getTime()) || (verifiedJwt.exp * 1000) >= oneYearForward.getTime())
        {
            errorMessages.push("Missing or invalid exp parameter in signed_metadata.")
        }
        if (!verifiedJwt.hasOwnProperty("jti")) {
            errorMessages.push("Missing or invalid jti parameter in signed_metadata.")
        }
        if (!verifiedJwt.hasOwnProperty("authorization_endpoint") && udapWellKnownJson.hasOwnProperty("authorization_endpoint")) {
            errorMessages.push("Missing authorization_endpoint parameter in signed_metadata.")
        }
        if (!verifiedJwt.hasOwnProperty("token_endpoint")) {
            errorMessages.push("Missing or invalid token_endpoint parameter in signed_metadata.")

            if (!verifiedJwt.hasOwnProperty("registration_endpoint")) {
                errorMessages.push("Missing or invalid registration_endpoint parameter in signed_metadata.")
            }
        }
        if (errorMessages.length == 0) {
            return verifiedJwt
        }
        else {
            return null
        }
    }

    //Creates a signed software statement for UDAP Trusted Dynamic Client Registration
    createUdapSignedSoftwareStatement(registerUrl, registrationClaims,signingAlg) {
        var found = udapCommon.validateSanInCert(registrationClaims.san, this.communityCert)
        if (found == false) {
            throw new udapClientError("Requested SAN not found in client cert")
        }
        else {
            var claims = {
                iss: registrationClaims.san,
                sub: registrationClaims.san,
                aud: registerUrl,
                client_name: registrationClaims.client_name,
                token_endpoint_auth_method: 'private_key_jwt',
                grant_types: registrationClaims.grant_types,
                response_types: registrationClaims.response_types,
                redirect_uris: registrationClaims.redirect_uris,
                contacts: registrationClaims.contacts,
                logo_uri: registrationClaims.logo_uri,
                scope: registrationClaims.scope
            }
            console.log("Claims for software statement:")
            console.log(claims)
            var token = udapCommon.generateUdapSignedJwt(claims, this.communityKeypair,signingAlg)
            return token
        }
    }

    //Creates a signed jwt authentication token.  It is added as the client_assertion claim
    createUdapSignedAuthenticationToken(tokenUrl,signingAlg) {
        const claims = {
            iss: this.clientId,
            sub: this.clientId,
            aud: tokenUrl,
            'extensions': {
                'hl7-b2b': {
                    version: '1',
                    organization_id: this.organizationId,
                    organization_name: this.organizationName,
                    purpose_of_use: [this.purposeOfUse]
                }
            }
        }
        var token = udapCommon.generateUdapSignedJwt(claims, this.communityKeypair,signingAlg)
        return token
    }
}
module.exports = udapClient