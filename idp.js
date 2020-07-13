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

// If we do not modify crypto related stuff, we may use a JWT library that does the heavy lifting for us -> TODO: Implement capabilities for crypto related attacks
const jwt = require("jsonwebtoken");
const privateKey = fs.readFileSync('private_unencrypted.pem');

// Express web framework
const express = require("express");
let app = express();

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
  let id_token = jwt.sign(payload, privateKey, {algorithm: 'RS256'});
  return id_token;
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
let jwksResponse = {};
let registrationResponse = {};

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
  
  // TODO: Implement

  res.json(jwksResponse);
});

// registration endpoint
app.get("/register", function (req, res) {
  console.log(`  [${req.ip}] registration endpoint`);
  console.log(`      [*] Data to be sent: ${JSON.stringify(registrationResponse)}`);
  
  // TODO: Implement

  res.json(registrationResponse);
});

/////////////////////////////////////////////////////////////////////////////////////////

app.listen(3000, function () {
  console.log("[+] Example IdP listening for HTTP  on Port 3000 :-)");
});

https.createServer(options, app).listen(3001);
console.log("[+] Example IdP listening for HTTPS on Port 3001 :-)");