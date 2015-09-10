# `gobservatory`

![](https://i.imgur.com/RFMFgWU.jpg)

A Go re-write of the SSL Observatory, because Go rules and is perfect for this
task, and hey, I'm a masochist I guess...

##  Basic workflow

```
                      * MS root pool
                      * NSS root pool
                      * Trans root pool    * asn finder

                             ^                  ^
                             |                  |
                             v                  v

 <-> submission api -> validity checker -> meta generator -> database <-> query api

           ^                                                    ^
           |                                                    |
           v                                                    v

     * ocsp checker                                      periodic updater
     * crl checker
     * database (revocation checking)                           ^
                                                                |
                                                                v

                                                         * ocsp checker
                                                         * crl checker
```

## Performance

With a single submission processor on my machine I'm able to attain about ~30
submissions/second, with two processors I can get ~60-70 submissions/second. This
is as far as I've tested so far.

## TODO

### Random

- [ ] Switch from SHA 256 to old weird fingerprinting method in order to back-compatible
  so we can seed the new schema from the old database
- [ ] Reject absurdly large chains (if this is submission size based we can avoid
  the below requirement I think...)
- [ ] Add a method to check & truncate certificates if certain fields are too large
  (and add some bool to the base Certificate model to represent if this has happened)
  to prevent attacks where someone just constructs insanely massive certificates
  we have to parse
- [x] YAML config
- [ ] Root pool retreival/loading tools
  - [x] Basic load from PEM method
  - [ ] Parsers
    - [ ] [NSS root list](https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt)
      retriever/parser/loader (agl has a good [ref. tool](https://github.com/agl/extract-nss-root-certs))
    - [ ] MS root list retriever/parser/loader (catt has a useful set of scripts [here](https://github.com/kirei/catt/tree/master/scripts)
      to crib from))
    - [ ] Trans validity root list (I think this has to be pulled from observed certificates?)
  - [ ] Dynamic reloading of root pools (RPC?)
- [ ] [If available use OCSP to check if certificate is revoked](https://github.com/rolandshoemaker/gobservatory/blob/master/external/ocspChecker/ocsp.go)
  (periodically, Jeremy may already be working on this!)
- [ ] [If available check CRL](https://github.com/rolandshoemaker/gobservatory/blob/master/external/crlChecker/crl.go)
  (periodically)
- [ ] Send StatsD metrics somewhere
- [ ] Full test suite!
- [ ] Create tool to translate/seed new schema from old database
- [ ] Compare `gobservatory` performance to Python Observatory... (was it actually
  worth it?)

### Database

- [ ] [Database schema](https://github.com/rolandshoemaker/gobservatory/blob/master/db/schema.sql)
  - [ ] **General index/foreign key/performance review** (ask pde/jeremy/jeff/jcj/etc
    for advice on if the draft schema is viable)
  - [x] Report schema
  - [x] ASN schema
  - [x] Chain schema
  - [x] OCSP/CRL certificate revocation schema
  - [x] Various certificate schemas
    - [x] Basic certificates (still needs work and probably more splitting stuff out...)
    - [x] Key usage
    - [x] Raw certificates (DER)
    - [x] Subject key identifier
    - [x] Authority key identifier
    - [x] DNS names
    - [x] IPs
    - [x] Emails
    - [x] Subjects (Also split)
      - [x] Serial
      - [x] Common names
      - [x] Countries
      - [x] Organizations
      - [x] Organizational units
      - [x] Localities
      - [x] Provinces
    - [x] Subject extensions
    - [x] x509v3 extensions
    - [x] RSA public keys
    - [x] DSA public keys
    - [x] ECC public keys (only P-224, P-256, P-384, and P-521 curves)
    - [x] IssuingCertificateURL
    - [x] OCSP endpoints
    - [x] CRL endpoints
    - [x] Policy OIDs
    - [x] DNS name constraints
  - [ ] Inverse index mapping schemas (names -> certs, some of the cert splitting
    seems to basically accomplish this for us)
- [x] Create database models for every schema
- [x] Add/Update methods for models
  - [x] Add ASN
  - [x] Add chain
  - [x] Add (split) certificate
    - [x] Basic section
    - [x] Raw certificate
    - [x] Basically everything else...
    - [x] Certificate extensions
    - [x] Subject extensions
  - [x] Add submission report

### [Submission API](https://github.com/rolandshoemaker/gobservatory/blob/master/api/submission/submission.go)

- [x] Backwards compatibility with previous API (and therefore HTTPS Everywhere
  and SSL Observatory Funnel)
- [x] HTTP server
- [x] HTTPS server
- [x] Submission handler
- [x] [Query for ASN number and name if server IP available](https://github.com/rolandshoemaker/gobservatory/blob/master/external/asnFinder/asn.go)
- [x] Generate submission reports
- [ ] Support all submission parameters (ASN/opt out/etc)
- [ ] Actually do what all the parameters indicate
- [x] Check that none of the certificates have been revoked before responding to client
- [x] Graceful shutdown

### Chain parsing

- [x] Generate valid chains for different root pools
  - [x] Check trans-validity
