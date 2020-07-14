# Custom OpenID Connect Identity Provider
Custom and flexible OpenID Connect IdP for research and PoC purposes - built with Node.js.

## Setup
```Bash
user@laptop:/$ git clone https://github.com/lauritzh/oidc-custom-idp
[...]
user@laptop:/$ cd oidc-custom-idp/
user@laptop:/oidc-custom-idp$ node idp.js 
[+] Example IdP listening for HTTPS on Port 3001 :-)
[+] Example IdP listening for HTTP  on Port 3000 :-)

```
(This requires Node.js on your machine)

You may add "127.0.0.1 poc.local" to your `/etc/hosts`-file, so that you can reach the IdP at https://poc.local:3001/
