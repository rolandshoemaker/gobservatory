CREATE TABLE `asns` (
  `number` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `last_seen` datetime NOT NULL,
  KEY (`number`)
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

CREATE TABLE `chains` (
  `fingerprint` binary(36) NOT NULL,
  `first_generated` datetime NOT NULL,
  `last_generated` datetime NOT NULL,
  `nss_valid` tinyint(1) NOT NULL,
  `ms_valid` tinyint(1) NOT NULL,
  `trans_valid` tinyint(1) NOT NULL,
  `valid` tinyint(1) NOT NULL,
  `count` count bigint(20) NOT NULL,
  PRIMARY KEY (`fingerprint`)
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

CREATE TABLE `unparsable_certificates` (
  `fingerprint` binary(36) NOT NULL,
  `der` blob NOT NULL,
  `reason` varchar(256) NOT NULL,
  PRIMARY KEY (`fingerprint`)
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

CREATE TABLE `certificates` (
  `fingerprint` binary(36) NOT NULL,
  `valid` tinyint(1) NOT NULL,
  `version` tinyint(1) NOT NULL,
  'serial' varchar(256) NOT NULL,
  `root` tinyint(1) NOT NULL,
  `basic_constraints` tinyint(1) NOT NULL,
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

CREATE TABLE `raw_certificates` (
  `certificate_fingerprint` binary(36) NOT NULL,
  `der` blob NOT NULL,
  KEY `fingerprint_idx` (`certificate_fingerprint`),
  CONSTRAINT `fingerprint_raw_certificates` FOREIGN KEY (`certificate_fingerprint`) REFERENCES `certificates` (`fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

CREATE TABLE `dns_names` (
  `certificate_serial` varchar(256) NOT NULL,
  `name` varchar(256) NOT NULL,
  `wildcard` tinyint(1) NOT NULL,
  KEY `serial_idx` (`certificate_serial`),
  CONSTRAINT `serial_dns_names` FOREIGN KEY (`certificate_serial`) REFERENCES `certificates` (`serial`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

CREATE TABLE `ip_addresses` (
  `certificate_serial` varchar(256) NOT NULL,
  `ip` varchar(256) NOT NULL,
  KEY `serial_idx` (`certificate_serial`),
  CONSTRAINT `serial_ip_addresses` FOREIGN KEY (`certificate_serial`) REFERENCES `certificates` (`serial`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

CREATE TABLE `email_addresses` (
  `certificate_serial` varchar(256) NOT NULL,
  `email` varchar(256) NOT NULL,
  KEY `serial_idx` (`certificate_serial`),
  CONSTRAINT `serial_email_addresses` FOREIGN KEY (`certificate_serial`) REFERENCES `certificates` (`serial`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

CREATE TABLE `countries` (
  `certificate_serial` varchar(256) NOT NULL,
  `country` varchar(256) NOT NULL,
  KEY `serial_idx` (`certificate_serial`),
  CONSTRAINT `serial_countries` FOREIGN KEY (`certificate_serial`) REFERENCES `certificates` (`serial`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

CREATE TABLE `organizations` (
  `certificate_serial` varchar(256) NOT NULL,
  `organization` varchar(256) NOT NULL,
  KEY `serial_idx` (`certificate_serial`),
  CONSTRAINT `serial_organizations` FOREIGN KEY (`certificate_serial`) REFERENCES `certificates` (`serial`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

CREATE TABLE `organizational_units` (
  `certificate_serial` varchar(256) NOT NULL,
  `organizational_unit` varchar(256) NOT NULL,
  KEY `serial_idx` (`certificate_serial`),
  CONSTRAINT `serial_organizational_units` FOREIGN KEY (`certificate_serial`) REFERENCES `certificates` (`serial`) ON DELETE CASCADE ON UPDATE NO ACTION

) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

CREATE TABLE `localities` (
  `certificate_serial` varchar(256) NOT NULL,
  `locality` varchar(256) NOT NULL,
  KEY `serial_idx` (`certificate_serial`),
  CONSTRAINT `serial_localities` FOREIGN KEY (`certificate_serial`) REFERENCES `certificates` (`serial`) ON DELETE CASCADE ON UPDATE NO ACTION

) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

CREATE TABLE `provinces` (
  `certificate_serial` varchar(256) NOT NULL,
  `province` varchar(256) NOT NULL,
  KEY `serial_idx` (`certificate_serial`),
  CONSTRAINT `serial_provinces` FOREIGN KEY (`certificate_serial`) REFERENCES `certificates` (`serial`) ON DELETE CASCADE ON UPDATE NO ACTION

) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

CREATE TABLE `street_addresses` (
  `certificate_serial` varchar(256) NOT NULL,
  `street_address` varchar(256) NOT NULL,
  KEY `serial_idx` (`certificate_serial`),
  CONSTRAINT `serial_street_addresses` FOREIGN KEY (`certificate_serial`) REFERENCES `certificates` (`serial`) ON DELETE CASCADE ON UPDATE NO ACTION

) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

CREATE TABLE `postal_codes` (
  `certificate_serial` varchar(256) NOT NULL,
  `postal_code` varchar(256) NOT NULL,
  KEY `serial_idx` (`certificate_serial`),
  CONSTRAINT `serial_postal_codes` FOREIGN KEY (`certificate_serial`) REFERENCES `certificates` (`serial`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

CREATE TABLE `subject_extensions` (
  `id` varchar(256) NOT NULL,
  'value' blob NOT NULL,
  `certificate_serial` varchar(256) NOT NULL,
  KEY `serial_idx` (`certificate_serial`),
  CONSTRAINT `serial_subject_extensions` FOREIGN KEY (`certificate_serial`) REFERENCES `certificates` (`serial`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

CREATE TABLE `certificate_extensions` (
  `critical` tinyint(1) NOT NULL,
  `id` varchar(256) NOT NULL,
  'value' blob NOT NULL,
  `certificate_serial` varchar(256) NOT NULL,
  KEY `serial_idx` (`certificate_serial`),
  CONSTRAINT `serial_certificate_extensions` FOREIGN KEY (`certificate_serial`) REFERENCES `certificates` (`serial`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

CREATE TABLE `ocsp_endpoints` (
  `certificate_fingerprint` binary(36) NOT NULL,
  `endpoint` varchar(256) NOT NULL,
  KEY `fingerprint_idx` (`certificate_fingerprint`),
  CONSTRAINT `fingerprint_ocsp_endpoint` FOREIGN KEY (`certificate_fingerprint`) REFERENCES `certificates` (`fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;

CREATE TABLE `crl_endpoints` (
  `certificate_fingerprint` binary(36) NOT NULL,
  `endpoint` varchar(256) NOT NULL,
  KEY `fingerprint_idx` (`certificate_fingerprint`),
  CONSTRAINT `fingerprint_crl_endpoint` FOREIGN KEY (`certificate_fingerprint`) REFERENCES `certificates` (`fingerprint`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=UTF8;
