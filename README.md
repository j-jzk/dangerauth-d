# DangerAuth
DangerAuth is a mechanism for secure authentication over insecure channels, for example if you want client authentication over HTTP.

This is the CLI client, written in D.
It has been written as a proof of concept and its design is flawed (see note in the _Authentication model_ section).
Don't rely on it for important data.

## Usage
See `./dangerauth -h`.

## Authentication model
This program generates a short-lived code based on a secret key (which is possibly encrypted by a symmetric password).

The code _cc_ is created as the HMAC signature of the current timestamp divided by 30 seconds (=> the code is valid in a 30-second window).
When _cc_ is transfrerred to the server, it similarly generates its own code _cs_ using the same private key.
If the keys match, the client has been successfully authenticated.

Please note that this authentication model fails if:  
1. the attacker manages to make use of the code in the 30-second window,
2. or subsequent commands aren't authenticated. The attacker can simply steal the session ID, which is transferred over the insecure channel.

Because of this, the program is basically useless in practice.

