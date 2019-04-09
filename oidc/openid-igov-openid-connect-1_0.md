# TODO
 * Further detail the use case / context; use case as in first OAuth2 iGov-NL profile, but explicitly with user authentication and identification.
 * guideline for caching metadata
 * steps in the flow not yet detailed in this profile
 * check refs, source iGov OIDC profile looks somewhat inconsistent with iGov OAuth2 profile
 * explicit access token is JWT, as per OAuth2 iGov-NL?

# NOTES
 * Note: explicit redirect_uri registration part of OAuth (iGov-NL profile)
 * Note: original iGov example are inconsistent or even invalid
 * Note: Replaced 'OpenID Connect identity provider' usages with 'OpenID Provider'
 * Note: Removed all references to vtr, vot
 * Note: Removed iGov-NL ... /iGov-NL tags.
 


# Abstract

The OpenID Connect protocol defines an identity federation system that allows
a relying party to request and receive authentication and profile information
about an end user.

This specification profiles the OpenID Connect protocol to increase baseline
security, provide greater interoperability, and structure deployments in a
manner specifically applicable to (but not limited to) government and public
service domains **in the Netherlands**.

This profile builds on top of, and inherits all properties of, the OAUTH
profile for iGov **in the Netherlands ("iGov-NL")**.

* * *

# Use case

As in the original OAuth iGov profile, this profile focuses on a Relying Party 
also known as a Client. As OpenID Connect is not explicitly applicable to 
Resource Servers, they are left out of scope. 

The generic use case where this profile can be applied, is very similar to the 
use case for the iGov-NL OAuth2 profile.

_A Client application wishes to identify *and* authenticate a User and may also 
want to receive User attributes from a trusted party._

Client applications are restricted to web applications in this version of the 
profile. Future updates may add support for native applications.

# Flow for identification and authentication
The flow starts identical to the use case flow of the OAuth2 iGov-NL profile. 
As with iGov-NL OAuth2, only the authorization code flow is supported in this profile.
Step 1 to 5 of that profile can be applied as-is, with the distinction that the 
Authorization Request explicitly is an Authentication Request.

Step 6 will result in an Access Token and ID Token. The Access Token can be used 
in a UserInfo Request or in requests to a Resource Server as in regular OAuth2.

In addition to the ID Token, the Client can make a UserInfo Request. This request 
can be used to obtain additional information about the User.

Step 7 (Oauth2) is optional or implied. The Relying Party (the Client) can use the 
authentication result directly -- effectively resulting in resource server integrated 
in the Client -- or can make requests to a Resource Server using the obtained Access 
Token as in the OAuth2 use case.


#  1. Introduction

Government regulations for permitting users (citizens and non-citizens) online
access to government resources vary greatly from region to region. There is a
strong desire to leverage federated authentication and identity services for
public access to government resources online to improve user experiences, reduce 
'password fatigue', increase overall account security, reduce costs, and provide 
reliable identity assurances from established and trusted sources when applicable.

This specification aims to define an OpenID Connect profile that provides government 
organizations and parties working with government organizations in the Netherlands 
with a foundation for securing federated access to public services online.

**This document is derived from the iGov profile by the OpenID Foundation.**

##  1.1. Requirements Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 .

All uses of JSON Web Signature (JWS) and JSON Web Encryption (JWE) data
structures in this specification utilize the JWS Compact Serialization or the
JWE Compact Serialization; the JWS JSON Serialization and the JWE JSON
Serialization are not used.

##  1.2. Terminology

This specification uses the terms "Access Token", "Authorization Code",
"Authorization Endpoint", "Authorization Grant", "Authorization Server",
"Client", "Client Authentication", "Client Identifier", "Client Secret",
"Grant Type", "Protected Resource", "Redirection URI", "Refresh Token",
"Resource Owner", "Resource Server", "Response Type", and "Token Endpoint"
defined by OAuth 2.0 , the terms "Claim Name", "Claim Value", and "JSON Web
Token (JWT)" defined by JSON Web Token (JWT) , and the terms defined by OpenID
Connect Core 1.0 .

##  1.3. Conformance

This specification defines requirements for the following components:

  * OpenID Connect 1.0 relying parties, also known as OpenID Clients 
  * OpenID Connect 1.0 identity providers, also known as OpenID Providers

The specification also defines features for interaction between these
components:

  * Relying party to OpenID Provider

When an iGov-**NL**-compliant party is interacting with another iGov-**NL**-compliant
party, in any valid combination, all parties MUST fully conform to the features and 
requirements of this specification. All interaction with non-iGov-**NL**
components is outside the scope of this specification.

An iGov-**NL**-compliant OpenID Provider MUST support all required features as described 
in this specification. A general-purpose OpenID Provider MAY support additional features 
for use with non-iGov-**NL** clients.

An iGov-**NL**-compliant OpenID Provider MAY also provide iGov-compliant OAuth 2.0
authorization server functionality. In such cases, the authorization server
MUST fully implement the OAuth 2.0 iGov-**NL** profile. If an iGov-compliant OpenID
Provider does not provide iGov-compliant OAuth 2.0 authorization server
services, all features related to interaction between the authorization server
and protected resources are therefore OPTIONAL.

An iGov-**NL**-compliant OpenID Connect client MUST implement all requirements as  
described in this specification. A general-purpose client library MAY support 
additional features for use with non-iGov-**NL** IdPs.

#  2. Relying Party Profile

##  2.1. Authentication Request - Requests to the Authorization Endpoint

The iGov-**NL** OAuth2 profile specifies requirements for requests to Authorization
Endpoints - for example, when to use the PKCE parameters to secure token
exchange.

In addition to the requirements specified in Section ~~2.1.1~~ **1.3.1.1 (?)** of the iGov-**NL** OAuth2
profile, the following describes the supported OpenID Connect Authorization
Code Flow parameters for use with iGov-**NL** compatible OpenID Providers.

Request Parameters:

* client_id

      REQUIRED. OAuth 2.0 Client Identifier valid at the Authorization Server. 
* response_type
    
      REQUIRED. MUST be set to 'code'.
* scope 
      
      REQUIRED. Indicates the attributes being requested. (See below) 
* redirect_uri 
    
      REQUIRED. Indicates a valid endpoint where the Client will receive the authentication 
      response. See (core section 3.1.2.1) 
* state
      
      REQUIRED. Unguessable random string generated by the RP, used to protect against CSRF 
      attacks. Must contain a sufficient amount of entropy. Returned, unchanged, to the RP 
      in the authentication response. 
* nonce
    
      REQUIRED. Unguessable random string generated by the client, used to protect against 
      CSRF attacks. Must contain a sufficient amount of entropy. Returned to the Client in 
      the ID Token. 

* acr_values
    
      OPTIONAL. Lists the acceptable LoAs for this authentication. See (below). 
* code_challenge and code_challenge_method
    
      OPTIONAL. If the PKCE protocol is being used by the client. See OAUTH profile for 
      iGov-NL.

A sample request may look like:
   
    https://op.example.com/oidc/authorization.endpoint?
      response_type=code
      &client_id=827937609728-m2mvqffo9bsefh4di90saus4n0diar2h
      &scope=openid+email
      &redirect_uri=https%3A%2F%2Frp.example.com%2Foidc%2FloginResponse
      &state=2ca3359dfbfd0
      &nonce=9d3252993a38454c8a6c3a4b86997aaa
      &acr_values=http%3A%2F%2Feidas.europa.eu%2FLoA%2Fsubstantial
    
###  2.1.1. Request Objects

Clients MAY optionally send requests to the authorization endpoint in JWT form
as defined by OpenID Connect, instead of http request parameters. 
Clients MAY send request objects either by value, in a http request parameter 
named `request` or by reference using the `request_uri` http request parameter.

Request objects MUST be signed by the client's registered key. Request objects
MAY be encrypted to the OpenID Provider's public key.

All iGov-NL comformant OpenID Providers MUST support signed request objects passed
by value at minimum and SHOULD also support request objects passed by reference.


In case request objects using pass by reference are used, the `request_uri` parameter 
value MUST be pre-registered. The URI MUST be using either a URN or an absolute HTTPS 
URI, and MUST contain a sufficient amount of entropy to avoid guessing.
To avoid attacks by `request_uri` manipulation, the base value of the URI MUST be 
registered prior to usage and SHOULD be unambiguously distinct from other URIs in use. 
Since the `request_uri` should at the same time differ for each unique request due to 
caching considerations, a HTTPS URI MUST use a parameter identifying the request object.
The `request_uri` value MUST be reachable or retrievable by the OP. The server hosting 
the `request_uri` MAY require authentication of the OP.


##  2.2. Token Request - Requests to the Token Endpoint

In addition to the requirements specified in Section ~~2.1.2~~ **1.3.1.2 (?)** of the iGov-**NL** OAuth2
profile, the following parameters MUST be included:

The following parameters are specified:

* grant_type

      REQUIRED. MUST be set to `authorization_code`.
    
* code

      REQUIRED. The value of the code parameter returned in the authorization response.

* client_assertion_type

  	REQUIRED when `private_key_jwt` client authentication method is used. MUST be 
  	set to `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.
	
* client_assertion

      REQUIRED when `private_key_jwt` client authentication method is used. The value of 
      the signed client authentication JWT generated as described below. The Client MUST  
      generate a new client_assertion JWT for each call to the token endpoint, JWTs MUST 
      NOT be reused. 

* client_id

      REQUIRED when `tls_client_auth` client authentication method is used. OAuth 2.0 Client 
      Identifier valid at the Authorization Server. 

* code_verifier

      REQUIRED when PKCE protocol was used by the Client in the relevant Authentication Request, 
      the code_verifier MUST be present and the value MUST be the original random code, used to 
      create the hashed challenge in `code_challenge`. 


##  2.3. ID Tokens

All clients MUST validate the signature of an ID Token before accepting it
using the public key of the issuing server, which is published in JSON Web Key
(JWK) format. ID Tokens SHOULD be encrypted using the appropriate key of the
requesting client.

Clients MUST verify the following in received ID tokens:

* iss

      The "issuer" URL of the OpenID Provider. 
* aud

      The "audience" field contains the client ID of the Relying Party. Clients MUST 
      validate that they are listed as an audience for ID tokens they process.
* exp, iat, nbf

      The "expiration", "issued at", and "not before" timestamps respectively for the token 
      are dates (integer number of seconds since from 1970-01-01T00:00:00Z UTC) within 
      acceptable ranges.
	
* nonce

      The "nonce" field MUST be used by Clients to detect/prevent CSRF, replay and other 
      attacks and Clients MUST verify that the nonce Claim Value is equal to the value of 
      the nonce parameter sent in the Authentication Request.
* acr

      Clients MUST validate the authentication context class reference, if present, satisfies 
      the minimum required before authorizing access to any resource or performing any 
      operation on behalf of the identified subject.



##  2.4. OpenID Provider Discovery

Clients can use openid configuration published by OpenID Providers to obtain information 
about OpenID Provider configurations. 

Clients and protected resources SHOULD cache OpenID Provider metadata, for a period 
determined by OpenID Provider configuration such as http headers or OpenID Provider policy, 
once an OP has been discovered and used by the client.


## 2.5 Client Registration

Clients SHOULD be able to perform dynamic registration. If dynamic registration is not 
supported, it is up to the discretion of the OpenID Provider whether and up to what level 
of detail an alternative process is provided.
Pre-conditions to registration of Clients with the OpenID Provider MAY be applicable, for 
various reasons such as organizational, legal, administrative, policy, security or 
technical reasons. Any such pre-conditions are out of scope of this profile.

Clients MUST be registered using the name of the responsible Service Provider and not any 
intermediary or supplier related names. The name MUST be familiar and MUST be clearly shown 
to the User both at the RP's website and at the OP.

### 2.5.1 PKIoverheid
In case the Relying Party and OpenID Provider are not operated under responsibility of the 
same organization, each party MUST use PKIoverheid certificates with OIN.

PKIoverheid certificates MUST be included as <code>x5c</code> parameters in client JWKs.
The <code>x5c</code> parameter MUST be included as a list (array) of X509 certificate(s), 
as Base64 DER encoded PKIoverheid certificate(s).
The first certificate MUST be the Client's certificate, optionally followed by the rest of 
that certificate's chain.
The jwks structure MUST include the public key parameters with the same values of the 
corresponding X509 certificate included as <code>x5c</code>, as per [RFC7517] §4.7.

## 2.6 Client Authentication

Authentication of the client using the private_key_jwt client authentication method MUST be 
supported by OpenID Providers. tls_client_auth method MAY also be supported by OpenID Providers.

NOTE: the client_secret_jwt method is not considered of equivalent security and the methods 
client_secret_basic and client_secret_post are obviously less secure. These three methods 
MUST NOT be used.

### 2.6.1 Private key JWT

A client can authenticate using private_key_jwt, by generating a JWT with contents as 
specified below and signing it with its private key. This method is specified in OIDC, 
https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication.

The JWT MUST contain the following:

* iss

      REQUIRED. MUST contain the Client id.
    
* sub

      REQUIRED. MUST contain the Client id.
* aud

      REQUIRED. Issuer URL for the OpenID Provider.

* jti

      REQUIRED. JWT id. MUST be unique and MUST NOT be reused. 
    
* exp

      REQUIRED. Expiration time on or after which the JWT MUST NOT be accepted for processing.
* iat

      REQUIRED. Time at which the JWT was issued.
    
An non-normative, example Token Request using private_key_jwt client authentication:

	grant_type=authorization_code&
	code=AzNx2xXGF5Tq6j4swOUY4T1kh4utXPBfMwRoGVMd&
	redirect_uri=https%3A%2F%2Flocalhost%3A8443%2Ftest%2Fa%2Fpkjwt_2_signedreq%2Fcallback&
	client_assertion=eyJraWQiOiJwa2p3dF8xX2sxIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJwa2p3dF8yX3
	NpZ25lZHJlcSIsImF1ZCI6Imh0dHBzOlwvXC8xOTIuMTY4LjEwMS4xMzA6OTAzMVwvYXNcL3Rva2VuLm9hdXRo
	MiIsImlzcyI6InBrand0XzJfc2lnbmVkcmVxIiwiZXhwIjoxNTQ0NDUwNTc3LCJpYXQiOjE1NDQ0NTA1MTcsIm
	p0aSI6ImpnYWl1ZUtLZnBvdjBsSUprWHp6In0.bAcg3hXoTQvEkE8QBVpecFqkxTLtPqPgti5IKhmWkQD8bbQb
	WFnVM_xepD_VttWxQataNtRPnuE_9QUO8B72uPPgEDE0u4aGt3UiApX_jzCxdO6MuZAYU8OpVYIaZDCAjQl-XR
	ZBz_LiVLo-JlwyEKI8w4tLqntLoi5myO0EK3OuMpIHnCumEersiACN1mu86sBmWhl4bFIJWpBiL17D2e7wRsTV
	cIzuwFsQJFk-KOBP3yh2x9QYdwlbMJt6kZTF0_8cqSDA_A8pQoO9w7MySP6YbEW4A_rb-VLFHEX3gTJ4ztTCKd
	81vL3iIgqeBO37WFL7uqI9PFxlRg635GBVfA&
	client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer


#  3. OpenID Provider Profile

##  3.1. ID Tokens

All ID Tokens MUST be signed by the OpenID Provider's private signature key.
ID Tokens MAY be encrypted using the appropriate key of the requesting client.
The OpenID Provider MUST support the RS256 signature algorithm (RSA signature 
algorithm with a 256-bit hash) and SHOULD support using the PS256 
(RSASSA-PSS using SHA-256 and MGF1 with SHA-256) and MAY use other asymmetric
signature and encryption algorithms, which provide equivalent or stronger 
security, listed in the JSON Web Algorithms (JWA) specification.

ID Tokens MUST expire and SHOULD have an active lifetime no longer than
five minutes. Since the ID token is consumed by the client and not presented
to remote systems, much shorter expiration times are RECOMMENDED where
possible.

ID Tokens contain the following claims at minimum and MAY contain other claims:

* iss

      REQUIRED. The "issuer" URL of the OpenID Provider. 
* aud

      REQUIRED. The "audience" field contains the client ID of the Relying Party. 
* sub

      REQUIRED. The user identifier, subject.  

* acr

      OPTIONAL. The LoA the user was authenticated at. MUST be a member of the 
      acr_values list from the authentication request **or that was agreed upon 
      through other means**. 
    
* nonce

      REQUIRED. MUST match the nonce value that was provided in the authentication 
      request. 
* jti

      REQUIRED. A unique identifier for the token, which can be used to prevent reuse 
      of the token. 
* auth_time

      RECOMMENDED. SHOULD be included if the OpenID Provider can assert an end-user's 
      authentication intent was demonstrated. For example, a login event where the user 
      took some action to authenticate. 
* exp, iat, nbf

      REQUIRED. The "expiration", "issued at", and "not before" timestamps respectively,  
      for the token are dates (integer number of seconds since from 1970-01-01T00:00:00Z  
      UTC) within acceptable ranges. 

This example ID token has been signed using the server's RSA key:
    
    
            eyJhbGciOiJSUzI1NiJ9.eyJhdXRoX3RpbWUiOjE0
            MTg2OTg3ODIsImV4cCI6MTQxODY5OTQxMiwic3ViI
            joiNldaUVBwblF4ViIsIm5vbmNlIjoiMTg4NjM3Yj
            NhZjE0YSIsImF1ZCI6WyJjMWJjODRlNC00N2VlLTR
            iNjQtYmI1Mi01Y2RhNmM4MWY3ODgiXSwiaXNzIjoi
            aHR0cHM6XC9cL2lkcC1wLmV4YW1wbGUuY29tXC8iL
            CJpYXQiOjE0MTg2OTg4MTJ9mQc0rtL56dnJ7_zO_f
            x8-qObsQhXcn-qN-FC3JIDBuNmP8i11LRA_sgh_om
            RRfQAUhZD5qTRPAKbLuCD451lf7ALAUwoGg8zAASI
            5QNGXoBVVn7buxPd2SElbSnHxu0o8ZsUZZwNpircW
            NUlYLje6APJf0kre9ztTj-5J1hRKFbbHodR2I1m5q
            8zQR0ql-FoFlOfPhvfurXxCRGqP1xpvLLBUi0JAw3
            F8hZt_i1RUYWMqLQZV4VU3eVNeIPAD38qD1fxTXGV
            Ed2XDJpmlcxjrWxzJ8fGfJrbsiHCzmCjflhv34O22
            zb0lJpC0d0VScqxXjNTa2-ULyCoehLcezmssg

Its claims are as follows:

    
    
    {
        "iss": "https://idp-p.example.com/",
        "aud": [
               "c1bc84e4-47ee-4b64-bb52-5cda6c81f788"
               ],
        "sub": "6WZQPpnQxV",
        "nonce": "188637b3af14a",
        "acr":"http://eidas.europa.eu/LoA/substantial",
        "auth_time": 1418698782,
        "iat": 1418698812,
        "nbf": 1418698812,
        "exp": 1418699412,
        "jti": "b42e57f8-4cfa-474a-afed-f0e9a77880c9"
    }
            

##  3.2. Identifier Types

The Netherlands has standardized on using a citizen identification number
(_BurgerServiceNummer_ or BSN), for citizen to government related
interactions. Usage of the BSN is restricted by Dutch law. The BSN therefor
SHOULD be protected by additional security controls. For example, a BSN in
the `sub` parameter can be encrypted to the Relying Party.

A `sub` containing a BSN SHOULD be considered `subject_type=public`.
For use cases where the BSN is not explicitly applicable, alternative
identifiers SHOULD be used. Such subject identifiers can be either public
or pairwise, depending on the identifier and use case. An OP conforming to
this profile SHOULD support public identifiers.

It is expected that the sub claim will remain pseudonymous in use cases 
where obtaining personal information is not needed.


##  3.3. UserInfo Endpoint

OpenID Providers MUST support the UserInfo Endpoint and, at a minimum, the sub
claim. 

Support for a UserInfo Endpoint is important for maximum client implementation
interoperability even if no additional user information is returned. Clients
are not required to call the UserInfo Endpoint, but should not receive an
error if they do.

In an example transaction, the client sends a request to the UserInfo Endpoint
like the following:

    
    
    GET /userinfo HTTP/1.1
    Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE0MTg3MDI0MTIsIm
    F1ZCI6WyJjMWJjODRlNC00N2VlLTRiNjQtYmI1Mi01Y2RhNmM4MWY3ODgiXSwiaXNzIjo
    iaHR0cHM6XC9cL2lkcC1wLmV4YW1wbGUuY29tXC8iLCJqdGkiOiJkM2Y3YjQ4Zi1iYzgx
    LTQwZWMtYTE0MC05NzRhZjc0YzRkZTMiLCJpYXQiOjE0MTg2OTg4MTJ9i.HMz_tzZ90_b
    0QZS-AXtQtvclZ7M4uDAs1WxCFxpgBfBanolW37X8h1ECrUJexbXMD6rrj_uuWEqPD738
    oWRo0rOnoKJAgbF1GhXPAYnN5pZRygWSD1a6RcmN85SxUig0H0e7drmdmRkPQgbl2wMhu
    -6h2Oqw-ize4dKmykN9UX_2drXrooSxpRZqFVYX8PkCvCCBuFy2O-HPRov_SwtJMk5qjU
    WMyn2I4Nu2s-R20aCA-7T5dunr0iWCkLQnVnaXMfA22RlRiU87nl21zappYb1_EHF9ePy
    q3Q353cDUY7vje8m2kKXYTgc_bUAYuW-W3SMSw5UlKaHtSZ6PQICoA
    Accept: text/plain, application/json, application/*+json, */*
    Host: op.example.com
    Connection: Keep-Alive
    
    

And receives a document in response like the following:

    
    
    HTTP/1.1 200 OK
    Date: Tue, 16 Dec 2014 03:00:12 GMT
    Access-Control-Allow-Origin: *
    Content-Type: application/json;charset=ISO-8859-1
    Content-Language: en-US
    Content-Length: 333
    Connection: close
    
    {
       "sub": "6WZQPpnQxV",
       "iss": "https://op.example.com"
       "given_name": "Stephen",
       "family_name": "Emeritus",
    }
    

OpenID Providers SHOULD support the generation of JWT encoded responses from the
UserInfo Endpoint in addition to unsigned JSON objects. Signed responses MUST
be signed by the OpenID Provider's key, and encrypted responses MUST be
encrypted with the authorized Client's public key. The OpenID Provider MUST
support the RS256 signature algorithm (RSA signature algorithm with a 256-bit hash) 
and SHOULD support using the PS256 (RSASSA-PSS using SHA-256 and MGF1 with SHA-256) 
and MAY use other asymmetric signature and encryption algorithms, which provide 
equivalent or better security, listed in the JSON Web Algorithms (JWA) specification.


##  3.4. Request Objects

OpenID Providers MUST accept requests containing a signed `request` parameter, 
signed by the Client's private key. OpenID Providers MUST validate the 
signature on signed request objects against the Client's registered public key. 
OpenID Providers SHOULD accept request objects encrypted with the server's 
public key.

OpenID Providers MAY accept request objects by reference using the request_uri
parameter.

Both of these methods allow for clients to create a request that is protected
from tampering through the browser, allowing for a higher security mode of
operation for clients and applications that require it. Clients are not
required to use request objects. 

OpenID Providers MUST support signed request objects passed by value and MAY 
support other encryption and parameter combinations.


In case request objects using pass by reference are used, the `request_uri` parameter 
value MUST be pre-registered. The URI MUST be using either a URN or an absolute HTTPS 
URI and MUST contain a sufficient amount of entropy to avoid guessing.
To avoid attacks by `request_uri` manipulation, the base value of the URI MUST be 
registered prior to usage and SHOULD be unambiguously distinct from other URIs in use.
The `request_uri` value MUST be reachable or retrievable by the OP. The OP MUST support 
authenticating to the server hosting the `request_uri`.



##  3.5. Authentication Context

OpenID Providers SHOULD provide acr (authentication context class reference, equivalent 
to the Security Assertion Markup Language (SAML) element of the same name) and amr 
(authentication methods reference) values in ID tokens.

As Europe has standardized on level-of-assurance (LoA) policies under eIDAS, 
the `acr` element is RECOMMENDED to be used. Valid values vary depending on 
context, use case and OpenID Providers in use. RECOMMENDED is to apply the 
three eIDAS LoAs (low, substantial and high), using the respective URIs 
defined by eIDAS as values.


##  3.6. Discovery

OpenID Connect Discovery specification provides a standard, programmatic way for
clients to obtain configuration details for communicating with OpenID
Providers. Discovery is an important part of building scalable federation
ecosystems.

Exposing a Discovery endpoint does NOT inherently put the OpenID Provider at
risk to attack. Endpoints and parameters specified in the Discovery document
SHOULD be considered public information regardless of the existence of the
Discovery document.

Access to the Discovery document MAY be protected with existing web
authentication methods if required by the OpenID Provider. Credentials for the
Discovery document are then managed by the OpenID Provider. Support for these
authentication methods is outside the scope of this specification.

Endpoints described in the Discovery document MUST be secured in accordance
with this specification and MAY have additional controls the Provider wishes to
support.

The discovery document MUST contain at minimum the following fields:

* issuer

      REQUIRED. The fully qualified issuer URL of the OpenID Provider. 
* authorization_endpoint

      REQUIRED. The fully qualified URL of the OpenID Provider's authorization endpoint 
      as defined by [RFC6749]. 
* token_endpoint

      REQUIRED. The fully qualified URL of the server's token endpoint as defined by 
      [RFC6749]. 

* userinfo_endpoint

      REQUIRED. The fully qualified URL of the server's user info endpoint as defined by 
      [OpenID.Discovery].


* introspection_endpoint

      OPTIONAL. The fully qualified URL of the server's introspection endpoint as defined by 
      OAuth Token Introspection. 
* revocation_endpoint

      OPTIONAL. The fully qualified URL of the server's revocation endpoint as defined by 
      OAuth Token Revocation. 
* jwks_uri

      REQUIRED. The fully qualified URI of the server's public keys in JWK Set format. 
      To be used for verifying the signatures on the id_token. 
* scopes_supported

      REQUIRED. The list of scopes, including iGov-NL scopes, the server supports. 
      This list may not contain all supported scopes, a minimal set of common scopes 
      can be provided if it is not possible to provide a list of all supported scopes. 
* response_types_supported

      REQUIRED. MUST only contain `code`, since only authorization code flow is supported by 
      this profile.
* claims_supported

      REQUIRED. The list of supported claims. 
      This list may not contain all supported scopes, a minimal set of common claims 
      can be provided if it is not possible to provide a list of all claims scopes. 


* acr_values_supported

      OPTIONAL. The acr values supported. 


* require_request_uri_registration

      REQUIRED only when passing request objects by reference is supported, MUST be set to `true`. 
      Either a URN or absolute HTTPS URI is required to be registered in case passing request 
      objects by reference will be used.



The following non-normative example shows the JSON document found at a discovery endpoint
for an OpenID Provider:

    
    
    {
      "id_token_encryption_alg_values_supported": [
        "RSA-OAEP", "RSA-OAEP-256"
      ],
      "userinfo_signing_alg_values_supported": [
        "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"
      ],
      "token_endpoint": "https://op.example.com/token",
      "request_parameter_supported": true,
      "request_uri_parameter_supported": false,
      "request_object_encryption_enc_values_supported": [
        "A192GCM", "A128GCM", "A256GCM"
      ],
      "token_endpoint_auth_methods_supported": [
        "private_key_jwt",
      ],
      "userinfo_encryption_alg_values_supported": [
        "RSA-OAEP", 
        "RSA-OAEP-256"
      ],
      "subject_types_supported": [
        "public", "pairwise"
      ],
      "id_token_encryption_enc_values_supported": [
        "A192GCM", "A128GCM", "A256GCM"
      ],
      "claims_parameter_supported": false,
      "jwks_uri": "https://op.example.com/jwk",
      "id_token_signing_alg_values_supported": [
        "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"
      ],
      "authorization_endpoint": "https://op.example.com/authorize",
      "require_request_uri_registration": true,
      "introspection_endpoint": "https://op.example.com/introspect",
      "request_object_encryption_alg_values_supported": [
        "RSA-OAEP", "RSA-OAEP-256"
      ],
      "service_documentation": "https://op.example.com/about",
      "response_types_supported": [
        "code"
      ],
      "token_endpoint_auth_signing_alg_values_supported": [
        "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"
      ],
      "revocation_endpoint": "https://op.example.com/revoke",
      "request_object_signing_alg_values_supported": [
        "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"
      ],
      "claim_types_supported": [
        "normal"
      ],
      "grant_types_supported": [
        "authorization_code",
      ],
      "scopes_supported": [
        "profile", "openid"
      ],
      "userinfo_endpoint": "https://op.example.com/userinfo",
      "userinfo_encryption_enc_values_supported": [
        "A192GCM", "A128GCM", "A256GCM"
      ],
      "op_tos_uri": "https://op.example.com/about",
      "issuer": "https://op.example.com/",
      "op_policy_uri": "https://op.example.com/about",
      "claims_supported": [
        "sub", "name", "acr"
      ],
      "acr_values_supported": [
		  "http://eidas.europa.eu/LoA/substantial",
		  "http://eidas.europa.eu/LoA/high"
	  ]
    }
    

It is RECOMMENDED that servers provide cache information through HTTP headers
and make the cache valid for at least one week.



### 3.6.1. JWKS 
The server MUST provide its public key in JWK Set format, such as the
following 2048-bit RSA key:

    
    {
      "keys": [
        {
          "alg": "RS256",
          "e": "AQAB",
          "n": "o80vbR0ZfMhjZWfqwPUGNkcIeUcweFyzB2S2T-hje83IOVct8gVg9Fx
                vHPK1ReEW3-p7-A8GNcLAuFP_8jPhiL6LyJC3F10aV9KPQFF-w6Eq6V
                tpEgYSfzvFegNiPtpMWd7C43EDwjQ-GrXMVCLrBYxZC-P1ShyxVBOze
                R_5MTC0JGiDTecr_2YT6o_3aE2SIJu4iNPgGh9MnyxdBo0Uf0TmrqEI
                abquXA1-V8iUihwfI8qjf3EujkYi7gXXelIo4_gipQYNjr4DBNl
                E0__RI0kDU-27mb6esswnP2WgHZQPsk779fTcNDBIcYgyLujlcUATEq
                fCaPDNp00J6AbY6w",
          "kty": "RSA",
          "kid": "rsa1",
		  "x5c": "MIIFdDCCA1ygAwIBAgIEAJiiOTANBgkqhkiG9w0BAQsFA                
		          ...
		          QFH1T/U67cjF68IeHRaVesd+QnGTbksVtzDfqu1XhUisH
		          94B7IWcnMFk="
        }
      ]
    }

#### 3.6.1.1. PKIoverheid
In case the Relying Party and the OpenID Provider are not operated under 
responsibility of the same organization, each party MUST use PKIoverheid 
certificates with OIN.

The PKIoverheid certificate MUST be included as a <code>x5c</code> parameter.
The <code>x5c</code> parameter MUST be included as a list (array) of X509 
certificate(s), as Base64 DER encoded PKIoverheid certificate(s).
The first certificate MUST be the Client's certificate, optionally followed 
by the rest of that certificate's chain.
The jwks structure MUST include the public key parameters with the same values
of the corresponding X509 certificate included as <code>x5c</code>, as per 
[RFC7517] §4.7.

##  3.7. Dynamic Client Registration

If the OpenID Provider is acting as an iGov-**NL** OAuth Authorization Server 
(iGov-**NL** OAuth2 profile) and if Dynamic Client Registration is supported, 
then Dynamic Client Registration MUST be supported in accordance with that
specification (see section 1.4.1.3).

##  3.8. Client Authentication

OpenID Providers MUST support private_key_jwt and SHOULD support tls_client_auth. 

#  4. User Info

The availability, quality, and reliability of a subject's attributes will vary 
greatly across jurisdictions and OpenID Provider systems. The following 
recommendations aims to ensure maximum interoperability, while setting Client 
expectations on the type of data they may acquire.

##  4.1. Claims Supported

Discovery mandates the inclusion of the claims_supported field that defines
the claims a client MAY expect to receive for the supported scopes. However, 
an OpenID Provider asserting it can provide a claim does not imply that this 
data is available to all clients at all times. Clients MUST be able to handle
cases where they don't receive all claims they requested or expected.

OpenID Providers MAY return claims outside of the claims_supported list, but 
they MUST ensure that the extra claims do not violate applicable privacy policies.

##  4.2. Scopes

In the interests of data minimization, balanced with the requirement to
successfully identify the individual signing in to a service, using the 
default OpenID Connect scopes and standard claims may not be appropriate.

OpenID Providers MUST ensure that only a minimum required set of scopes 
and associated claims are provided to Clients.
OpenID Providers are not required to support any standard scopes, defined in
OpenID.Core other than openid.


##  4.3. Claims Request

OpenID.Core section 5.5 defines a method for a client to request specific
claims. OpenID Providers SHOULD support this claims parameter in the interest 
of data minimization - that is, the OpenID Provider only
returns information on the subject the client specifically asks for, and does
not volunteer additional information about the subject.

OpenID Providers not supporting the claims parameter MUST also ensure that 
only a minimal, allowed for the Client by OpenID Provider policy, and consented 
by the End-User, set of claims are provided to Clients.


##  4.4. UserInfo Response

Response to a UserInfo request MUST match the scope and/or claims requested. 
OpenID Providers MUST ensure that excessive information is not provided.


#  5. Privacy Considerations

Data minimization is an essential concept in trust frameworks and federations
exchanging user identity information for government applications. This specification 
takes into consideration mechanisms to protect the user's government identity 
information and activity from unintentional exposure.

All parties implementing this specification MUST ensure that due care is taken 
to protect user privacy.

Pairwise anonymous identifiers MAY be supported by the OpenID Providers for
cases where subjects should not be traceable across clients by their subject 
identifiers. This prevents a situation where a user may inadvertently be assigned 
a universal government identifier.


#  6. Security Considerations

All transactions MUST be protected in transit by TLS as described in BCP195.

In addition to the Best Current Practice for TLS, it is RECOMMENDED for all 
conforming implementations to incorporate the TLS guidelines from the Dutch 
NCSC into their implementations.
For backchannel communication, the guidelines categorized as "good" MUST be 
applied.
For frontchannel communication, the guidelines for "good" SHOULD be applied 
and the guidelines for "sufficient" MAY be applied, depending target audience 
and support requirements.
Guidelines categorized as "insufficient" MUST NOT be applied and those 
categorized as "deprecated" SHOULD NOT be used.


All clients MUST conform to applicable recommendations found in the Security
Considerations sections of [RFC6749] and those found in the OAuth 2.0 Threat
Model and Security Considerations document.

#  7. Normative References

**[BCP195]** |  Sheffer, Y., Holz, R. and P. Saint-Andre, "[Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)](https://tools.ietf.org/html/rfc7525)", BCP 195, RFC 7525, DOI 10.17487/RFC7525, May 2015.  
---|---  
**[HEART.OAuth2]** |  [Richer, J.](mailto:openid@justin.richer.org), "[Health Relationship Trust Profile for OAuth 2.0](http://openid.net/specs/openid-heart-oauth2-1_0.html)", April 2017.  
**[I-D.ietf-oauth-pop-architecture]** |  Hunt, P., Richer, J., Mills, W., Mishra, P. and H. Tschofenig, "[OAuth 2.0 Proof-of-Possession (PoP) Security Architecture](https://tools.ietf.org/html/draft-ietf-oauth-pop-architecture-08)", Internet-Draft draft-ietf-oauth-pop-architecture-08, July 2016.  
**[iGov.OAuth2]** |  [Richer, J.](mailto:openid@justin.richer.org), "[iGov Profile for OAuth 2.0](http://openid.net/specs/openid-igov-oauth2-1_0.html)", October 2018.  
**[OpenID.Core]** |  Sakimura, N., Bradley, J., Jones, M., de Medeiros, B. and C. Mortimore, "[OpenID Connect Core 1.0](http://openid.net/specs/openid-connect-core-1_0.html)", August 2015.  
**[OpenID.Discovery]** |  Sakimura, N., Bradley, J., Jones, M. and E. Jay, "[OpenID Connect Discovery 1.0](http://openid.net/specs/openid-connect-discovery-1_0.html)", August 2015.  
**[RFC2119]** |  Bradner, S., "[Key words for use in RFCs to Indicate Requirement Levels](https://tools.ietf.org/html/rfc2119)", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997.  
**[RFC2246]** |  Dierks, T. and C. Allen, "[The TLS Protocol Version 1.0](https://tools.ietf.org/html/rfc2246)", RFC 2246, DOI 10.17487/RFC2246, January 1999.  
**[RFC3986]** |  Berners-Lee, T., Fielding, R. and L. Masinter, "[Uniform Resource Identifier (URI): Generic Syntax](https://tools.ietf.org/html/rfc3986)", STD 66, RFC 3986, DOI 10.17487/RFC3986, January 2005.  
**[RFC5246]** |  Dierks, T. and E. Rescorla, "[The Transport Layer Security (TLS) Protocol Version 1.2](https://tools.ietf.org/html/rfc5246)", RFC 5246, DOI 10.17487/RFC5246, August 2008.  
**[RFC5322]** |  Resnick, P., "[Internet Message Format](https://tools.ietf.org/html/rfc5322)", RFC 5322, DOI 10.17487/RFC5322, October 2008.  
**[RFC5646]** |  Phillips, A. and M. Davis, "[Tags for Identifying Languages](https://tools.ietf.org/html/rfc5646)", BCP 47, RFC 5646, DOI 10.17487/RFC5646, September 2009.  
**[RFC5785]** |  Nottingham, M. and E. Hammer-Lahav, "[Defining Well-Known Uniform Resource Identifiers (URIs)](https://tools.ietf.org/html/rfc5785)", RFC 5785, DOI 10.17487/RFC5785, April 2010.  
**[RFC6125]** |  Saint-Andre, P. and J. Hodges, "[Representation and Verification of Domain-Based Application Service Identity within Internet Public Key Infrastructure Using X.509 (PKIX) Certificates in the Context of Transport Layer Security (TLS)](https://tools.ietf.org/html/rfc6125)", RFC 6125, DOI 10.17487/RFC6125, March 2011.  
**[RFC6749]** |  Hardt, D., "[The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)", RFC 6749, DOI 10.17487/RFC6749, October 2012.  
**[RFC6750]** |  Jones, M. and D. Hardt, "[The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://tools.ietf.org/html/rfc6750)", RFC 6750, DOI 10.17487/RFC6750, October 2012.  
**[RFC6819]** |  Lodderstedt, T., McGloin, M. and P. Hunt, "[OAuth 2.0 Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819)", RFC 6819, DOI 10.17487/RFC6819, January 2013.  
**[RFC7009]** |  Lodderstedt, T., Dronia, S. and M. Scurtescu, "[OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009)", RFC 7009, DOI 10.17487/RFC7009, August 2013.  
**[RFC7033]** |  Jones, P., Salgueiro, G., Jones, M. and J. Smarr, "[WebFinger](https://tools.ietf.org/html/rfc7033)", RFC 7033, DOI 10.17487/RFC7033, September 2013.  
**[RFC7515]** |  Jones, M., Bradley, J. and N. Sakimura, "[JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)", RFC 7515, DOI 10.17487/RFC7515, May 2015.  
**[RFC7516]** |  Jones, M. and J. Hildebrand, "[JSON Web Encryption (JWE)](https://tools.ietf.org/html/rfc7516)", RFC 7516, DOI 10.17487/RFC7516, May 2015.  
**[RFC7517]** |  Jones, M., "[JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)", RFC 7517, DOI 10.17487/RFC7517, May 2015.  
**[RFC7518]** |  Jones, M., "[JSON Web Algorithms (JWA)](https://tools.ietf.org/html/rfc7518)", RFC 7518, DOI 10.17487/RFC7518, May 2015.  
**[RFC7519]** |  Jones, M., Bradley, J. and N. Sakimura, "[JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)", RFC 7519, DOI 10.17487/RFC7519, May 2015.  
**[RFC7636]** |  Sakimura, N., Bradley, J. and N. Agarwal, "[Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636)", RFC 7636, DOI 10.17487/RFC7636, September 2015.  
**[RFC7662]** |  Richer, J., "[OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)", RFC 7662, DOI 10.17487/RFC7662, October 2015.  
**[RFC7800]** |  Jones, M., Bradley, J. and H. Tschofenig, "[Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)](https://tools.ietf.org/html/rfc7800)", RFC 7800, DOI 10.17487/RFC7800, April 2016.  
**[RFC8485]** |  Richer, J. and L. Johansson, "[Vectors of Trust](https://tools.ietf.org/html/rfc8485)", RFC 8485, DOI 10.17487/RFC8485, October 2018.  
  
