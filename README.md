# `gobservatory`

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

## TODO

### Random

- [x] YAML config
- [ ] Root pool retreival/loading tools
  - [x] Basic load from PEM method
  - [ ] Generate trans-validity pool
  - [ ] Parsers
    - [ ] [NSS root list](https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt)
      retriever/parser/loader (agl has a good [ref. tool](https://github.com/agl/extract-nss-root-certs))
    - [ ] MS root list retriever/parser/loader (no idea where to get this, surely
      there is someone who has done this)
  - [ ] Dynamic reloading of root pools (RPC?)
- [ ] Periodic OCSP revocation checker (Jeremy may already be working on this!)
- [ ] Send StatsD metrics somewhere
- [ ] Full test suite!
- [ ] Create tool to translate/seed new schema from old
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
  - [ ] Various certificate schemas
    - [ ] Basic certificates (still needs work and probably more splitting stuff out...)
    - [x] Key usage
    - [x] Raw certificates (DER)
    - [x] Subject key identifier
    - [x] Authority key identifier
    - [x] DNS names
    - [x] IPs
    - [x] Emails
    - [x] Subjects (Also split)
      - [ ] Serial (?)
      - [x] Common names
      - [x] Countries
      - [x] Organizations
      - [x] Organizational units
      - [x] Localities
      - [x] Provinces
    - [ ] Issuer subjects (?)
      - [ ] Serial
      - [ ] Common names
      - [ ] Countries
      - [ ] Organizations
      - [ ] Organizational units
      - [ ] Localities
      - [ ] Provinces
    - [x] Subject extensions
    - [x] x509v3 extensions
    - [x] RSA public keys
    - [x] ECC public keys (only P-224, P-256, P-384, and P-521 curves)
    - [x] OCSP endpoints
    - [x] CRL endpoints
    - [x] Policy OIDs
    - [x] DNS name constraints
  - [ ] Inverse index mapping schemas (names -> certs, some of the cert splitting
    seems to basically accomplish this for us)
- [x] Create database models for every schema
- [ ] Add/Update methods for models
  - [x] Add ASN
  - [x] Add chain
  - [ ] Add (split) certificate
    - [x] Basic section
    - [x] Raw certificate
    - [ ] Everything else...
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
- [ ] Graceful shutdown

### Certificate/chain parsing

- [ ] Parse all the interesting stuff out of the certificates (basically just
  thanks Golang `^_^`)
  - [ ] Comply with schemas above
  - [ ] [If available use OCSP to check if certificate is revoked](https://github.com/rolandshoemaker/gobservatory/blob/master/external/ocspChecker/ocsp.go)
  - [ ] [If available check CRL](https://github.com/rolandshoemaker/gobservatory/blob/master/external/crlChecker/crl.go)
- [x] Generate valid chains for different root pools
  - [x] Check trans-validity (this is much more confusing than I first thought,
    I *think* my current implementation may work if the trans pool contains the
    needed intermediates, need to check with Jeremey...)
