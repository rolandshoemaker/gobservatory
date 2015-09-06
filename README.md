# `gobservatory`

A Go re-write of the SSL Observatory, because Go rules and is perfect for this
task, and hey, I'm a masochist I guess...

##  Basic workflow

```
      * MS root pool
      * NSS root pool

             ^
             |
             v

      submission api -> validity checker -> cert decomposer -> database <-> query api

             ^                  ^                                  ^
             |                  |                                  |
             v                  v                                  v

       * ocsp checker     * asn finder                      periodic updater
       * crl checker
                                                                   ^
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
- [ ] Compare `gobservatory` performance to Python Observatory

### Database

- [ ] [Database schema](https://github.com/rolandshoemaker/gobservatory/blob/master/db/schema.sql)
  - [ ] **General index/foreign key/performance review** (ask pde/jeremy/jeff/jcj/etc
    for advice on if the draft schema is viable)
  - [ ] Report schema
  - [x] ASN schema
  - [x] Chain schema
  - [x] OCSP/CRL certificate revocation schema
  - [ ] Various certificate schemas
    - [ ] Basic certificates (still needs work and probably more splitting and
      `SubjectKeyId` + `AuthorityKeyId` stuff...)
    - [ ] Key usage (or should this be in the main table?)
    - [x] Raw certificates (DER)
    - [x] Names
    - [x] IPs
    - [x] Emails
    - [x] Subjects (Also split)
    - [x] Subject extensions (how to handle extension content?)
    - [x] x509v3 extensions (how to handle extension content?)
    - [x] RSA public keys
    - [x] ECC public keys (only P-224, P-256, P-384, and P-521 curves)
    - [x] OCSP endpoints
    - [x] CRL endpoints
    - [ ] Policy OIDs
    - [x] DNS name constraints
  - [ ] Inverse index mapping schemas (names -> certs, some of the cert splitting
    seems to basically accomplish this for us)
- [ ] Create (gorp?) database models for everything
- [ ] Add/Update methods for models
  - [x] Add ASN
  - [ ] Add chain
  - [ ] Add (split) certificate

### [Submission API](https://github.com/rolandshoemaker/gobservatory/blob/master/api/submission/submission.go)

- [x] Backwards compatibility with previous API (and therefore HTTPS Everywhere
  and SSL Observatory Funnel)
- [x] HTTP server
- [x] HTTPS server
- [x] Submission handler
- [x] [Query for ASN number and name if server IP available](https://github.com/rolandshoemaker/gobservatory/blob/master/external/asnFinder/asn.go)
- [ ] Generate submission reports
- [ ] Support all submission parameters (ASN/opt out/etc)
- [ ] Actually do what all the parameters indicate
- [ ] Check that none of the certificates have been revoked before responding to client
- [ ] Graceful shutdown

### Certificate/chain parsing

- [ ] Parse all the interesting stuff out of the certificates (basically just
  thanks Golang `^_^`)
  - [ ] [If available use OCSP to check if certificate is revoked](https://github.com/rolandshoemaker/gobservatory/blob/master/external/ocspChecker/ocsp.go)
  - [ ] [If available check CRL](https://github.com/rolandshoemaker/gobservatory/blob/master/external/crlChecker/crl.go)
- [x] Generate valid chains for different root pools
  - [x] Check trans-validity (this is much more confusing than I first thought,
    I *think* my current implementation may work if the trans pool contains the
    needed intermediates, need to check with Jeremey...)
