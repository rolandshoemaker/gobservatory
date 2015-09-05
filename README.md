# `gobservatory`

A Go re-write of the SSL Observatory, because Go rules and is perfect for this task, and
hey, I'm a masochist I guess...

## TODO

- [ ] YAML config
- [ ] Database schema
- [ ] Submission API
  - [x] HTTP server
  - [ ] HTTPS server
  - [x] Submission handler
  - [ ] Support all submission parameters
  - [ ] Actually do what all the parameters indicate (ASN/opt out/etc)
  - [ ] Check that none of the certificates have been revoked before responding to client
- [ ] Root pool retreival tools
  - [ ] Basic load from PEM method (mostly for testing)
  - [ ] NSS root list parser/loader (agl has a good ref. tool)
  - [ ] MS root list parser/loader (no idea where to get this, surely there is someone who has done this)
- [ ] Create database models for everything
- [ ] Parse all the interesting stuff out of the certificates
  - [ ] If available use OCSP to check if certificate is revoked
  - [ ] Insert all the goodies into the various tables (or update them or do nothing)
- [x] Process valid chains for different root pools
  - [x] Check trans-validity
  - [ ] Insert chains into the database
- [x] Query for ASN number and name
  - [ ] Insert ASN stuff into the database
- [ ] Generate submission reports
  - [ ] Insert reports into the database
- [ ] Send StatsD metrics somewhere
- [ ] Full test suite!
