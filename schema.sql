-- ASNs
--   ASN numbers, names, and the last time it was seen by a HTTPS Everywhere
--   client.
--

CREATE TABLE `asns` (
  `number` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `last_seen` datetime NOT NULL,
  PRIMARY KEY (`number`)
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

-- Chains
--   Certificate chains either generated by Golang or directly submitted by various
--   sources and their NSS, MS, and trans validities. This table also tracks the number
--   of times the chain has been generated/submitted and when it was last generated
--   or submitted.
--

CREATE TABLE `chains` (
  `fingerprint` binary(36) NOT NULL,
  `first_seen` datetime NOT NULL,
  `last_seen` datetime NOT NULL,
  `nss_valid` tinyint(1) NOT NULL,
  `ms_valid` tinyint(1) NOT NULL,
  `trans_valid` tinyint(1) NOT NULL,
  `valid` tinyint(1) NOT NULL,
  `count` count bigint(20) NOT NULL,
  PRIMARY KEY (`fingerprint`)
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

-- Certificates
--   Basic certificates, most certificate properties are stripped out to seperate
--   tables what is left is the main key, 'fingerprint', and various other basic
--   information
--

CREATE TABLE `certificates` (
  `fingerprint` binary(36) NOT NULL,
  `valid` tinyint(1) NOT NULL,
  `version` tinyint(1) NOT NULL,
  'serial' varchar(256) NOT NULL,
  `root` tinyint(1) NOT NULL,
  `basic_constraints` tinyint(1) NOT NULL,
  `name_constraints_critical` tinyint(1) NOT NULL,
  `max_path_len` int(10) NOT NULL,
  `max_path_zero` tinyint(1) NOT NULL,
  `issuer_serial` varchar(256) NOT NULL,
  `signature_alg` tinyint(1) NOT NULL,
  `signature` blob NOT NULL,
  `not_before` datetime NOT NULL,
  `not_after` datetime NOT NULL,
  `common_name` varchar(256) NOT NULL,
  `revoked` tinyint(1) NOT NULL,
  `revoked_at` datetime DEFAULT NULL,
  `revoked_reason` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`fingerprint`),
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

-- Raw certificates
--   Raw DER content of certificate we have decomposed into all the other tables,
--   linked to the other certificate tables by the 'certificate_fingerprint' key.
--

CREATE TABLE `raw_certificates` (
  `certificate_fingerprint` binary(36) NOT NULL,
  `der` blob NOT NULL,
  KEY `fingerprint_idx` (`certificate_fingerprint`),
  CONSTRAINT `fingerprint_raw_certificates` FOREIGN KEY (`certificate_fingerprint`) REFERENCES `certificates` (`fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

-- DNS names
--   Contains DNS names taken from a certificate linked by the `certificate_fingerprint`
--   key. Also contains a bool to indicate if the name is a wildcard.
--

CREATE TABLE `dns_names` (
  `certificate_fingerprint` binary(36) NOT NULL,
  `name` varchar(256) NOT NULL,
  `wildcard` tinyint(1) NOT NULL,
  KEY `fingerprint_idx` (`certificate_fingerprint`),
  CONSTRAINT `fingerprint_dns_names` FOREIGN KEY (`fingerprint_serial`) REFERENCES `certificates` (`fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

-- IP addresses
--   Contains IP addresses taken from a certificate linked by the `certificate_fingerprint`
--   key.
--

CREATE TABLE `ip_addresses` (
  `certificate_fingerprint` binary(36) NOT NULL,
  `ip` varchar(256) NOT NULL,
  KEY `fingerprint_idx` (`certificate_fingerprint`),
  CONSTRAINT `fingerprint_ip_addresses` FOREIGN KEY (`certificate_fingerprint`) REFERENCES `certificates` (`fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

-- Email addresses
--   Contains email addresses taken from a certificate linked by the `certificate_fingerprint`
--   key.
--

CREATE TABLE `email_addresses` (
  `certificate_fingerprint` binary(36) NOT NULL,
  `email` varchar(256) NOT NULL,
  KEY `fingerprint_idx` (`certificate_fingerprint`),
  CONSTRAINT `fingerprint_email_addresses` FOREIGN KEY (`certificate_fingerprint`) REFERENCES `certificates` (`fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

-- Countries
--   Contains Subject CNs taken from a certificate linked by the `certificate_fingerprint`
--   key.
--

CREATE TABLE `countries` (
  `certificate_fingerprint` binary(36) NOT NULL,
  `country` varchar(256) NOT NULL,
  KEY `fingerprint_idx` (`certificate_fingerprint`),
  CONSTRAINT `fingerprint_countries` FOREIGN KEY (`certificate_fingerprint`) REFERENCES `certificates` (`fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

-- Organizations
--   Contains Subject Os taken from a certificate linked by the `certificate_fingerprint`
--   key.
--

CREATE TABLE `organizations` (
  `certificate_fingerprint` binary(36) NOT NULL,
  `organization` varchar(256) NOT NULL,
  KEY `fingerprint_idx` (`certificate_fingerprint`),
  CONSTRAINT `fingerprint_organizations` FOREIGN KEY (`certificate_fingerprint`) REFERENCES `certificates` (`fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

-- Organizational Units
--   Contains Subject OUs taken from a certificate linked by the `certificate_fingerprint`
--   key.
--

CREATE TABLE `organizational_units` (
  `certificate_fingerprint` binary(36) NOT NULL,
  `organizational_unit` varchar(256) NOT NULL,
  KEY `fingerprint_idx` (`certificate_fingerprint`),
  CONSTRAINT `fingerprint_organizational_units` FOREIGN KEY (`certificate_fingerprint`) REFERENCES `certificates` (`fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

-- Localities
--   Contains Subject Ls taken from a certificate linked by the `certificate_fingerprint`
--   key.
--

CREATE TABLE `localities` (
  `certificate_fingerprint` binary(36) NOT NULL,
  `locality` varchar(256) NOT NULL,
  KEY `fingerprint_idx` (`certificate_fingerprint`),
  CONSTRAINT `fingerprint_localities` FOREIGN KEY (`certificate_fingerprint`) REFERENCES `certificates` (`fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

-- Provinces
--   Contains Subject STs taken from a certificate linked by the `certificate_fingerprint`
--   key.
--

CREATE TABLE `provinces` (
  `certificate_fingerprint` binary(36) NOT NULL,
  `province` varchar(256) NOT NULL,
  KEY `fingerprint_idx` (`certificate_fingerprint`),
  CONSTRAINT `fingerprint_provinces` FOREIGN KEY (`certificate_fingerprint`) REFERENCES `certificates` (`fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

-- Subject extensions
--   Contains Subject extensions Golang doesn't parse taken from a certificate
--   linked by the `certificate_fingerprint` key.
--

CREATE TABLE `subject_extensions` (
  `certificate_fingerprint` binary(36) NOT NULL,
  `id` varchar(256) NOT NULL,
  'value' blob NOT NULL,
  KEY `fingerprint_idx` (`certificate_fingerprint`),
  CONSTRAINT `fingerprint_subject_extensions` FOREIGN KEY (`certificate_fingerprint`) REFERENCES `certificates` (`fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

-- x509v3 extensions
--   Contains x509v3 extensions taken from a certificate linked by the `certificate_fingerprint`
--   key.
--

CREATE TABLE `certificate_extensions` (
  `certificate_fingerprint` binary(36) NOT NULL,
  `critical` tinyint(1) NOT NULL,
  `id` varchar(256) NOT NULL,
  'value' blob NOT NULL,
  KEY `fingerprint_idx` (`certificate_fingerprint`),
  CONSTRAINT `fingerprint_certificate_extensions` FOREIGN KEY (`certificate_fingerprint`) REFERENCES `certificates` (`fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

-- OCSP endpoints
--   Contains OCSP endpoints taken from a certificate linked by the `certificate_fingerprint`
--   key.
--

CREATE TABLE `ocsp_endpoints` (
  `certificate_fingerprint` binary(36) NOT NULL,
  `endpoint` varchar(256) NOT NULL,
  KEY `fingerprint_idx` (`certificate_fingerprint`),
  CONSTRAINT `fingerprint_ocsp_endpoint` FOREIGN KEY (`certificate_fingerprint`) REFERENCES `certificates` (`fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

-- CRL endpoints
--   Contains CRL endpoints taken from a certificate linked by the `certificate_fingerprint`
--   key.
--

CREATE TABLE `crl_endpoints` (
  `certificate_fingerprint` binary(36) NOT NULL,
  `endpoint` varchar(256) NOT NULL,
  KEY `fingerprint_idx` (`certificate_fingerprint`),
  CONSTRAINT `fingerprint_crl_endpoint` FOREIGN KEY (`certificate_fingerprint`) REFERENCES `certificates` (`fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

-- Constrained DNS names
--   Contains constrained DNS names taken from a certificate linked by the
--   `certificate_fingerprint` key. Also contains a bool to indicate if the name
--   is a wildcard.
--

CREATE TABLE `constrained_names` (
  `certificate_fingerprint` binary(36) NOT NULL,
  `name` varchar(256) NOT NULL,
  KEY `fingerprint_idx` (`certificate_fingerprint`),
  CONSTRAINT `fingerprint_dns_names` FOREIGN KEY (`fingerprint_serial`) REFERENCES `certificates` (`fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;
