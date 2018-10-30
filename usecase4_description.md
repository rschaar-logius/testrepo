# Use case 4 - client interaction with API -- starting point


## Introduction
In this use case a (public/governmental) service is offered via an API.
The service will be consumed by the User using a client, that can be any arbitrary, non-trusted application.
For provisioning the service, the service provider requires an identifier of the User.
The identifier of the User can be either an arbitrary (self-registered) identifier or a formal identifier (citizen number or other restricted, registered ID).
Upon service provisioning, the service uses the identifier of the User for access control within the service.

## Context
### Resource Server
The service is provided by a public/governmental organization.
Assumed is the Resource Server is known (by the Authorization Server) prior to actual authentication/authorization of the User.
A Resource Server is assumed to posses a means for identification of the Resource Server and/or encrypted information, optionally by using a PKI certificate.

### Authorization / Authentication Server
An Authorization Server is available, operated by either an independent trusted third-party or the service provider itself.
Only a single Authorization Server is in use.
The Authorization Server is trusted by the Resource Server.
The Authorization Server can identify and authenticate the User.
In case the User has no direct relationship to the Authorization Server, it can forward the User to an IDP trusted by both the Authorization Server as well as the User.
Alternatively, the Authorization Server can identify and authenticate the User and is trusted by that User.


### Client
The User uses a client, which can be any arbitrary application decided upon by the User.
Assumed is that the User trusts this client for interaction with the service.
The Client is not trusted by the Resource Server.
   **TODO** public versus semi-confidential after pre-registration.
Assumptions is that the Client is aware of the specifications of the API and authorization is required.
The Client is either using a user-agent, typically a browser, or the relevant parts are integrated into the Client application.

Note:
Web-applications by default use the system-browser on a User's device as user-agent.
Typically a native application (_"mobile app"_) either starts a system browser as user-agent or uses an _in-app_ browser.
See RFC 8252 for more information on implementation of native applications.


## Flow for authentication
A Client wishes to send a request to an API, on behalf of the User.
The API requires to have a trusted identification of the User, before providing the Service.
A Client has pre-registered with the Authorization Endpoint and has been assigned a client_id.
    **TODO** ref pre-registration process/spec.

### Step 1. Authorization / authentication
As the client does not yet have a (valid) access token for this Service, it's first step is to obtain one.
Therefor it sends an Authorization Request to the Authorization Server's Authorization Endpoint.
It does so by redirecting / initiating the user-agent with the Authorization Request to the Authorization Endpoint.
The Authorization / Authentication request holds further details, as specified in this profile.

### Step 2. Authorization / authentication
The user-agent sends the Authorization / Authentication request to the Authentication Endpoint.
The Authorization Server receives and validates the request.

### Step 3. User Authentication and consent
The Authorization authenticates the User and obtains consent by the User for using the client to access the Service.
The method and means for authentication, as well as how to obtain consent of the User, are implementation specific and explicitly left out of scope of this profile.

### Step 4. Authorization Grant
Note: applicable to the Authorization Code Flow only.
The Authorization Server redirects the user-agent back to the Client, with a Authorization Response.
This Authorization Response holds an Authorization Grant and is send to the `redirect_uri` endpoint from the Authorization / Authentication request.

### Step 5. Token Request
Note: applicable to the Authorization Code Flow only.
The Client receives the Authorization Response from the user-agent.
Using the Authorization Grant from the response, the client sends a Token Request to the Authorization Server's token Endpoint.
It does so using the Client authentication as pre-registered.

### Step 6. Token Response


