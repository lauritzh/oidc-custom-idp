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
// Otherwise we craft the id_token using Node.js "crypto" + we need to encode stuff base64url manually
const crypto = require("crypto")
const base64url = require('base64url');

// Express.js web framework
const express = require("express");
let app = express();

/////////////////////////////////////////////////////////////////////////////////////////

// Constants
//// endpoints - add "127.0.0.1 poc.local" to your /etc/hosts file!
const authEndpoint = "https://poc.local:3001/auth";
const tokenEndpoint = "https://poc.local:3001/token";
const userinfoEndpoint = "https://poc.local:3001/userinfo";
const jwksEndpoint = "https://poc.local:3001/jwks";
const registrationEndpoint = "https://poc.local:3001/register";
const configurationEndpoint = "https://poc.local:3001/.well-known/openid-configuration";

//// claims
const iss = "https://poc.local:3001";
const sub = "TestUser";
const name = "Toni Test";
const email = "mail@lauritz-holtmann.de";
const exp = (Date.now() /1000 |0) + 3600; // https://stackoverflow.com/questions/221294/how-do-you-get-a-timestamp-in-javascript
const iat = (Date.now() /1000 |0);

//// client credentials
const client_id = "test.local";
const client_secret = "supersecret";

//// tokens
const access_token = "AccessToken";
const refresh_token = "RefreshToken"
const code = "code_abcde";

// SP provided Variables
let state = "";
let nonce = "";

// id_token
function createIdToken() {
  let payload = {"iss": iss, "aud": client_id, "sub": sub, "nonce": nonce, "exp": exp, "iat": iat}
  if(useJWTLib === true) {
    return jwt.sign(payload, privateKey, {algorithm: 'RS256'});
  } else {
    // key confusion attacks may be realized using this block: Additionally test JOSE header fields that may include key information such as "x5u", "x5c", "jku", and "jwk"
  
    // Example #1) "None" Algorithm: Exclude Signature (alternatively append Junk)
    //let header = {"alg": "None", "typ": "JWT"}
    //return base64url(JSON.stringify(header)) + "." + base64url(JSON.stringify(payload));


    // Example #2) RS256 signature generation using private key as secret
    let header = {"alg": "RS256", "typ": "JWT", "kid": "test"}
    
    // Prepare signed part of the JWT
    let toBeSigned = base64url(JSON.stringify(header)) + "." + base64url(JSON.stringify(payload));

    const signer = crypto.createSign('RSA-SHA256');
    signer.write(toBeSigned);
    signer.end();
    let signature = signer.sign(privateKey, 'base64');
    // we need base64url, thus we escape manually
    signature_escaped = base64url.fromBase64(signature);
    return toBeSigned + "." + signature_escaped;


    // Example #3) HS256 hmac generation (e.g. using asymmetric key parameters as secret)
    //let header = {"alg": "HS256", "typ": "JWT"}
    //let secret = "AQAB"; // we use "e" as example value

    // Prepare signed part of the JWT
    //let toBeSigned = base64url(JSON.stringify(header)) + "." + base64url(JSON.stringify(payload));

    //let hmac = crypto.createHmac("sha256", secret).update(toBeSigned).digest("base64");;
    // we need base64url, thus we escape manually
    //hmac_escaped = base64url.fromBase64(hmac);
    //return toBeSigned + "." + hmac_escaped;
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

let authResponse = `Redirecting...`;
let tokenResponse = {"access_token": access_token, "refresh_token": refresh_token, "token_type": "Bearer", "expires_in": "3600", "id_token": createIdToken()};
let userinfoResponse = {"sub": sub, "name": name, "email": email};
let configurationResponse = {"issuer": iss, "authorization_endpoint": authEndpoint, "token_endpoint": tokenEndpoint, "userinfo_endpoint": userinfoEndpoint, "jwks_uri": jwksEndpoint, "registration_endpoint": registrationEndpoint, "response_types_supported": ["code", "token id_token"], "subject_types_supported": ["public", "pairwise"], "id_token_signing_alg_values_supported": ["RS256"]}
let jwksResponse = {"keys": [{"kty":"RSA","e":"AQAB","kid":"test","use":"sig","n":"2PgMqqd9_xLENUu1wBAU5HwxicxiARAHw62IwGaRIlmFT5VOjt6dTY2SWcVxIafc0_2pUmeNQFyINkOwEGDdmj6a4MPmb9NuHaCniJUFmteIECIfqCRMW_-EoDs4h8rGarrjbYA7QFtk2oTyqE55OSPQkRsTFgRDjkHp9gYlCcFPmdbSa_xIqWmkyn_sZGVxuH0B05-17d1UujTb5hIp5hMyVRDG0bcpdlSUHrA3VdKHrscwAacWw86_DJsPv62OjuqPy5wKGQv8ulxJS9XRx47tlTUqerTUs1wGqFq3Ei_lj7DQ448vPmADjnWINjujU15QH9rSBHxIzCoLJ93nfcmAoXSx0TiJbG4BbCgTAAUW_xmylUamqY6lpquNtPwYysbgacVlhlsPGKNYqwseuQ1J7I_M3fleTi4_Sz9JHDWLQuKJ_Jxa7qcQLhmfg1s7fZZ_eNurrJcSbD9qPxa7K1SDNtHsGgOdSxUzcrOe4sFkP9gejG2vj4xqBw1-gdvnfbzcCKJ57EHQAuK9-cDtVWAABX0zaCrUFamCp01oYBi_T5ClLk1Yd-Hn_59U4PtWlDkifiCzI5aajqZV8f4mvP05TMxGT0FegEOxUJ0A_QOaFH3Og58CjIG3_MslZqAbkGOsWWZMu0KLM0Cdz0jLRsarYMmwcD2GZRXjI6wJVs8"}]};
let registrationResponse = {"client_id": client_id, "client_secret_expires_at": 0};

// we cannot precalculate the id_token, thus dynamically refresh the Token Response
function refreshTokenResponse() {
  tokenResponse = {"access_token": access_token, "refresh_token": refresh_token, "token_type": "Bearer", "expires_in": "3600", "id_token": createIdToken()};
}

/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////

// landing page
app.get("/", function (req, res) {
  console.log(`  [${req.ip}] landing page`);
  
  res.send(landingPage);
});

// auth endpoint
app.get("/auth", function (req, res) {
  console.log(`  [${req.ip}] auth endpoint (GET)`);
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

// userinfo endpoint
app.get("/userinfo", function (req, res) {
  console.log(`  [${req.ip}] userinfo endpoint`);
  console.log(`      [*] Data to be sent: ${JSON.stringify(userinfoResponse)}`);
  
  res.json(userinfoResponse);
});

// configuration endpoint
app.get("/.well-known/openid-configuration", function (req, res) {
  console.log(`  [${req.ip}] configuration endpoint`);
  console.log(`      [*] Data to be sent: ${JSON.stringify(configurationResponse)}`);
  
  res.json(configurationResponse);
});

// token endpoint
app.post("/token", function (req, res) {
  // craft token response based on provided nonce and fresh timestamps
  refreshTokenResponse();

  console.log(`  [${req.ip}] token endpoint`);
  console.log(`      [*] Data to be sent: ${JSON.stringify(tokenResponse)}`);
  
  res.json(tokenResponse);
});

// jwks endpoint
app.get("/jwks", function (req, res) {
  console.log(`  [${req.ip}] jwks endpoint`);
  console.log(`      [*] Data to be sent: ${JSON.stringify(jwksResponse)}`);

  res.json(jwksResponse);
});

// registration endpoint
app.get("/register", function (req, res) {
  console.log(`  [${req.ip}] registration endpoint`);
  console.log(`      [*] Data to be sent: ${JSON.stringify(registrationResponse)}`);
  
  res.status(204).send();
});

app.post("/register", function (req, res) {
  console.log(`  [${req.ip}] registration endpoint`);
  console.log(`      [*] Data to be sent: ${JSON.stringify(registrationResponse)}`);
  
  res.status(201);
  res.json(registrationResponse);
});
/////////////////////////////////////////////////////////////////////////////////////////

app.listen(3000, function () {
  console.log("[+] Example IdP listening for HTTP  on Port 3000 :-)");
});

https.createServer(options, app).listen(3001);
console.log("[+] Example IdP listening for HTTPS on Port 3001 :-)");