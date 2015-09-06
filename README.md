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

             ^                  ^               ^
             |                  |               |
             v                  v               v

       * ocsp checker     * asn finder   periodic updater
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
- [x] [Query for ASN number and name](https://github.com/rolandshoemaker/gobservatory/blob/master/external/asnFinder/asn.go)
- [ ] Periodic OCSP revocation checker (Jeremy may already be working on this!)
- [ ] Send StatsD metrics somewhere
- [ ] Full test suite!
- [ ] Create tool to translate/seed new schema from old
- [ ] Compare `gobservatory` performance to Python Observatory

### Database

- [ ] [Database schema](https://github.com/rolandshoemaker/gobservatory/blob/master/schema.sql)
  - [x] ASN schema
  - [x] Chain schema
  - [ ] Various certificate schemas
    - [ ] Basic certificates (still needs work and probably more splitting and
      `SubjectKeyId` + `AuthorityKeyId` stuff...)
    - [x] Raw certificates (DER)
    - [x] Names
    - [x] IPs
    - [x] Emails
    - [x] Subjects (Also split)
    - [x] Subject extensions
    - [x] x509v3 extensions
    - [ ] RSA Keys
    - [ ] ECC keys
    - [ ] Key usage
    - [x] OCSP endpoints
    - [x] CRL endpoints
    - [ ] Policy OIDs
    - [x] DNS name constraints
  - [ ] Inverse index mapping schemas (names -> certs, some of the cert splitting
    seems to basically accomplish this for us)
  - [ ] Reports schema
- [ ] Create (gorp?) database models for everything
- [ ] Add/Update methods for models

### [Submission API](https://github.com/rolandshoemaker/gobservatory/blob/master/api/submission/submission.go)

- [x] HTTP server
- [ ] HTTPS server
- [x] Submission handler
- [ ] Generate submission reports
- [ ] Support all submission parameters
- [ ] Actually do what all the parameters indicate (ASN/opt out/etc)
- [ ] Check that none of the certificates have been revoked before responding to client
- [ ] Graceful shutdown

### Certificate/chain parsing

- [ ] Parse all the interesting stuff out of the certificates
  - [ ] [If available use OCSP to check if certificate is revoked](https://github.com/rolandshoemaker/gobservatory/blob/master/external/ocspChecker/ocsp.go)
  - [ ] If available check CRL (?)
- [x] Generate valid chains for different root pools
  - [x] Check trans-validity (this is much more confusing than I first thought,
    I *think* my current implementation may work if the trans pool contain the
    needed intermediates, need to check with Jeremey...)
