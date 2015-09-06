# `gobservatory`

A Go re-write of the SSL Observatory, because Go rules and is perfect for this task, and
hey, I'm a masochist I guess...

## TODO

- [x] YAML config
- [ ] [Database schema](https://github.com/rolandshoemaker/gobservatory/blob/master/schema.sql)
  - [x] ASN schema
  - [x] Chain schema
  - [ ] Split certificate schemas (Names/IPs/Emails/Subjects/RSA Keys/ECC keys/Key usage/etc etc etc...)
  - [ ] Inverse index mapping schemas (names -> certs) etc
  - [ ] Reports schema
  - [ ] Create (gorp?) database models for everything
- [ ] Submission API
  - [x] HTTP server
  - [ ] HTTPS server
  - [x] Submission handler
  - [ ] Support all submission parameters
  - [ ] Actually do what all the parameters indicate (ASN/opt out/etc)
  - [ ] Check that none of the certificates have been revoked before responding to client
  - [ ] Graceful shutdown
- [ ] Root pool retreival tools
  - [x] Basic load from PEM method
  - [ ] Parsers
    - [ ] [NSS root list](https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt) retriever/parser/loader (agl has a good [ref. tool](https://github.com/agl/extract-nss-root-certs))
    - [ ] MS root list retriever/parser/loader (no idea where to get this, surely there is someone who has done this)
  - [ ] Dynamic reloading of root pools (RPC?)
- [ ] Parse all the interesting stuff out of the certificates
  - [ ] [If available use OCSP to check if certificate is revoked](https://github.com/rolandshoemaker/gobservatory/blob/master/external/ocspChecker/ocsp.go)
  - [ ] If available check CRL (?)
  - [ ] Insert all the goodies into the various tables (or update them or do nothing)
- [x] Process valid chains for different root pools
  - [ ] Check trans-validity (this is much more confusing than I first thought, I *think* my current implementation may work if the root lists contain the needed intermediates, need to check with Jeremey...)
  - [ ] Insert chains into the database
- [x] [Query for ASN number and name](https://github.com/rolandshoemaker/gobservatory/blob/master/external/asnFinder/asn.go)
  - [ ] Insert ASN stuff into the database
- [ ] Generate submission reports
  - [ ] Insert reports into the database
- [ ] Periodic OCSP revocation checker (Jeremy may already be working on this!)
- [ ] Send StatsD metrics somewhere
- [ ] Full test suite!
- [ ] Compare `gobservatory` performance to Python Observatory
- [ ] Create tool to translate/seed new schema from old...
