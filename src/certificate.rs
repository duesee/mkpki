use std::{borrow::Cow, net::Ipv4Addr, str::FromStr};

use bitvec::prelude::*;
use chrono::{Local, SubsecRound, TimeDelta};
use rand::{CryptoRng, Rng};
use rasn::{
    der::{decode, encode},
    types::{
        Any, BitString, GeneralizedTime, Ia5String, Integer, IntegerType, ObjectIdentifier,
        OctetString, Open::Null, PrintableString, SetOf,
    },
};
use rasn_pkix::{
    AlgorithmIdentifier, AttributeTypeAndValue, AuthorityKeyIdentifier, BasicConstraints,
    Certificate, CertificateSerialNumber, ExtKeyUsageSyntax, Extension, GeneralName,
    GeneralSubtree, Name, NameConstraints, RelativeDistinguishedName, SubjectAltName,
    SubjectPublicKeyInfo, TbsCertificate, Time, Validity, Version,
};
use rsa::{traits::PublicKeyParts, Pkcs1v15Sign, RsaPrivateKey};
use sha2::{Digest, Sha256};

use crate::gen_key;

pub const COUNTRY_NAME: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 4, 6]));
pub const ORGANIZATION_NAME: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 4, 10]));
pub const COMMON_NAME: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 4, 3]));
pub const KEY_USAGE: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 29, 15]));
pub const EXT_KEY_USAGE: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 29, 37]));
pub const SERVER_AUTH: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 3, 6, 1, 5, 5, 7, 3, 1]));
pub const CLIENT_AUTH: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 3, 6, 1, 5, 5, 7, 3, 2]));
pub const BASIC_CONSTRAINTS: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 29, 19]));
pub const SUBJECT_KEY_IDENTIFIER: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 29, 14]));
pub const AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 29, 35]));
pub const SUBJECT_ALT_NAME: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 29, 17]));
pub const RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 2, 840, 113549, 1, 1, 1]));
pub const SHA_256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 2, 840, 113549, 1, 1, 11]));
pub const NAME_CONSTRAINTS: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 29, 30]));

#[derive(Debug, rasn::AsnType, rasn::Encode)]
struct RsaPubKey {
    n: Integer,
    e: Integer,
}

pub fn gen_root<R: CryptoRng + Rng>(
    rng: &mut R,
    country_name: &[u8],
    organization_name: &[u8],
    common_name: &[u8],
) -> (RsaPrivateKey, Certificate) {
    let (sk, pk) = gen_key(rng, 4096);

    let cert = {
        let tbs_certificate = {
            let subject = Name::RdnSequence(vec![
                RelativeDistinguishedName::from(SetOf::from(vec![AttributeTypeAndValue {
                    r#type: COUNTRY_NAME,
                    value: Any::new(
                        encode(&PrintableString::from_bytes(country_name).unwrap()).unwrap(),
                    ),
                }])),
                RelativeDistinguishedName::from(SetOf::from(vec![AttributeTypeAndValue {
                    r#type: ORGANIZATION_NAME,
                    value: Any::new(
                        encode(&PrintableString::from_bytes(organization_name).unwrap()).unwrap(),
                    ),
                }])),
                RelativeDistinguishedName::from(SetOf::from(vec![AttributeTypeAndValue {
                    r#type: COMMON_NAME,
                    value: Any::new(
                        encode(&PrintableString::from_bytes(common_name).unwrap()).unwrap(),
                    ),
                }])),
            ]);

            let subject_public_key = {
                let pk = {
                    RsaPubKey {
                        n: Integer::try_from_unsigned_bytes(
                            &pk.n().to_bytes_be(),
                            rasn::Codec::Der,
                        )
                        .unwrap(),
                        e: Integer::try_from_unsigned_bytes(
                            &pk.e().to_bytes_be(),
                            rasn::Codec::Der,
                        )
                        .unwrap(),
                    }
                };

                BitVec::from_vec(encode(&pk).unwrap())
            };

            let skid = {
                let hash = {
                    let mut hasher = Sha256::new();
                    hasher.update(encode(&subject_public_key).unwrap());
                    hasher.finalize()
                };

                OctetString::from(hash.to_vec())
            };

            let key_usage = bitvec![u8, Msb0; 0, 0, 0, 0, 0, 1, 1];

            TbsCertificate {
                version: Version::V3,
                serial_number: CertificateSerialNumber::try_from_bytes(
                    &rng.r#gen::<[u8; 16]>(),
                    rasn::Codec::Der,
                )
                .unwrap(),
                signature: AlgorithmIdentifier {
                    algorithm: SHA_256_WITH_RSA_ENCRYPTION,
                    parameters: Some(Any::new(encode(&Null).unwrap())),
                },
                // This certificate is self-signed.
                issuer: subject.clone(),
                validity: validity_now_plus_days(50 * 365),
                subject,
                subject_public_key_info: SubjectPublicKeyInfo {
                    algorithm: AlgorithmIdentifier {
                        algorithm: RSA_ENCRYPTION,
                        parameters: Some(Any::new(encode(&Null).unwrap())),
                    },
                    subject_public_key,
                },
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: Some(
                    vec![
                        Extension {
                            extn_id: BASIC_CONSTRAINTS,
                            critical: true,
                            extn_value: encode(&BasicConstraints {
                                ca: true,
                                path_len_constraint: None,
                            })
                            .unwrap()
                            .into(),
                        },
                        Extension {
                            extn_id: KEY_USAGE,
                            critical: true,
                            extn_value: OctetString::from(encode(&key_usage).unwrap()),
                        },
                        Extension {
                            extn_id: SUBJECT_KEY_IDENTIFIER,
                            critical: false,
                            extn_value: OctetString::from(encode(&skid).unwrap()),
                        },
                        Extension {
                            extn_id: NAME_CONSTRAINTS,
                            critical: true,
                            extn_value: OctetString::from(
                                encode(&NameConstraints {
                                    permitted_subtrees: Some(vec![GeneralSubtree {
                                        base: GeneralName::DnsName(
                                            // TODO
                                            Ia5String::from_iso646_bytes(b"example.org").unwrap(),
                                        ),
                                        minimum: Default::default(),
                                        maximum: None,
                                    }]),
                                    excluded_subtrees: None,
                                })
                                .unwrap(),
                            ),
                        },
                    ]
                    .into(),
                ),
            }
        };

        let signature_algorithm = AlgorithmIdentifier {
            algorithm: SHA_256_WITH_RSA_ENCRYPTION,
            parameters: Some(Any::new(encode(&Null).unwrap())),
        };

        let signature_value = sign_tbs_certificate(&sk, &tbs_certificate);

        Certificate {
            tbs_certificate,
            signature_algorithm,
            signature_value,
        }
    };

    (sk, cert)
}

pub fn gen_intermediate<R: CryptoRng + Rng>(
    rng: &mut R,
    root_key: &RsaPrivateKey,
    root_cert: &Certificate,
    country_name: &[u8],
    organization_name: &[u8],
    common_name: &[u8],
    name_constraint: &[u8],
) -> (RsaPrivateKey, Certificate) {
    let (sk, pk) = gen_key(rng, 4096);

    let cert = {
        let tbs_certificate = {
            let subject = Name::RdnSequence(vec![
                RelativeDistinguishedName::from(SetOf::from(vec![AttributeTypeAndValue {
                    r#type: COUNTRY_NAME,
                    value: Any::new(
                        encode(&PrintableString::from_bytes(country_name).unwrap()).unwrap(),
                    ),
                }])),
                RelativeDistinguishedName::from(SetOf::from(vec![AttributeTypeAndValue {
                    r#type: ORGANIZATION_NAME,
                    value: Any::new(
                        encode(&PrintableString::from_bytes(organization_name).unwrap()).unwrap(),
                    ),
                }])),
                RelativeDistinguishedName::from(SetOf::from(vec![AttributeTypeAndValue {
                    r#type: COMMON_NAME,
                    value: Any::new(
                        encode(&PrintableString::from_bytes(common_name).unwrap()).unwrap(),
                    ),
                }])),
            ]);

            let subject_public_key = {
                let pk = {
                    RsaPubKey {
                        n: Integer::try_from_unsigned_bytes(
                            &pk.n().to_bytes_be(),
                            rasn::Codec::Der,
                        )
                        .unwrap(),
                        e: Integer::try_from_unsigned_bytes(
                            &pk.e().to_bytes_be(),
                            rasn::Codec::Der,
                        )
                        .unwrap(),
                    }
                };

                BitVec::from_vec(encode(&pk).unwrap())
            };

            let akid: OctetString = {
                decode(
                    root_cert
                        .tbs_certificate
                        .extensions
                        .as_ref()
                        .unwrap()
                        .iter()
                        .find(|e| e.extn_id == SUBJECT_KEY_IDENTIFIER)
                        .unwrap()
                        .extn_value
                        .clone()
                        .as_ref(),
                )
                .unwrap()
            };

            let skid = {
                let hash = {
                    let mut hasher = Sha256::new();
                    hasher.update(encode(&subject_public_key).unwrap());
                    hasher.finalize()
                };

                OctetString::from(hash.to_vec())
            };

            // TODO: Minimize?
            let key_usage = bitvec![u8, Msb0; 1, 0, 0, 0, 0, 1, 1];

            TbsCertificate {
                version: Version::V3,
                serial_number: CertificateSerialNumber::try_from_bytes(
                    &rng.r#gen::<[u8; 16]>(),
                    rasn::Codec::Der,
                )
                .unwrap(),
                signature: AlgorithmIdentifier {
                    algorithm: SHA_256_WITH_RSA_ENCRYPTION,
                    parameters: Some(Any::new(encode(&Null).unwrap())),
                },
                issuer: root_cert.tbs_certificate.subject.clone(),
                validity: validity_now_plus_days(25 * 365),
                subject,
                subject_public_key_info: SubjectPublicKeyInfo {
                    algorithm: AlgorithmIdentifier {
                        algorithm: RSA_ENCRYPTION,
                        parameters: Some(Any::new(encode(&Null).unwrap())),
                    },
                    subject_public_key,
                },
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: Some(
                    vec![
                        Extension {
                            extn_id: BASIC_CONSTRAINTS,
                            critical: true,
                            extn_value: encode(&BasicConstraints {
                                ca: true,
                                path_len_constraint: Some(0.into()),
                            })
                            .unwrap()
                            .into(),
                        },
                        Extension {
                            extn_id: KEY_USAGE,
                            critical: true,
                            extn_value: OctetString::from(encode(&key_usage).unwrap()),
                        },
                        Extension {
                            extn_id: EXT_KEY_USAGE,
                            critical: false,
                            // TODO: Minimize?
                            extn_value: encode(&ExtKeyUsageSyntax::from(&[
                                CLIENT_AUTH,
                                SERVER_AUTH,
                            ]))
                            .unwrap()
                            .into(),
                        },
                        Extension {
                            extn_id: SUBJECT_KEY_IDENTIFIER,
                            critical: false,
                            extn_value: OctetString::from(encode(&skid).unwrap()),
                        },
                        Extension {
                            extn_id: AUTHORITY_KEY_IDENTIFIER,
                            critical: false,
                            extn_value: OctetString::from(
                                encode(&AuthorityKeyIdentifier {
                                    key_identifier: Some(akid),
                                    authority_cert_issuer: None,
                                    authority_cert_serial_number: None,
                                })
                                .unwrap(),
                            ),
                        },
                        // TODO: authorityInfoAccess
                        // TODO: cRLDistributionPoints
                        // TODO: certificatePolicies
                        Extension {
                            extn_id: NAME_CONSTRAINTS,
                            critical: true,
                            extn_value: OctetString::from(
                                encode(&NameConstraints {
                                    permitted_subtrees: Some(vec![GeneralSubtree {
                                        base: GeneralName::DnsName(
                                            Ia5String::from_iso646_bytes(name_constraint).unwrap(),
                                        ),
                                        minimum: Default::default(),
                                        maximum: None,
                                    }]),
                                    excluded_subtrees: None,
                                })
                                .unwrap(),
                            ),
                        },
                    ]
                    .into(),
                ),
            }
        };

        let signature_algorithm = AlgorithmIdentifier {
            algorithm: SHA_256_WITH_RSA_ENCRYPTION,
            parameters: Some(Any::new(encode(&Null).unwrap())),
        };

        let signature_value = sign_tbs_certificate(&root_key, &tbs_certificate);

        Certificate {
            tbs_certificate,
            signature_algorithm,
            signature_value,
        }
    };

    (sk, cert)
}

pub fn gen_leaf<R: CryptoRng + Rng>(
    rng: &mut R,
    intermediate_key: &RsaPrivateKey,
    intermediate_cert: &Certificate,
    ipv4_or_domain_domain: &[u8],
) -> (RsaPrivateKey, Certificate) {
    let (sk, pk) = gen_key(rng, 2048);

    let cert = {
        let tbs_certificate = {
            let subject =
                Name::RdnSequence(vec![RelativeDistinguishedName::from(SetOf::from(vec![
                    AttributeTypeAndValue {
                        r#type: rasn::types::Oid::JOINT_ISO_ITU_T_DS_ATTRIBUTE_TYPE_COMMON_NAME
                            .into(),
                        value: Any::new(
                            encode(&PrintableString::from_bytes(ipv4_or_domain_domain).unwrap())
                                .unwrap(),
                        ),
                    },
                ]))]);

            let subject_public_key = {
                let pk = {
                    RsaPubKey {
                        n: Integer::try_from_unsigned_bytes(
                            &pk.n().to_bytes_be(),
                            rasn::Codec::Der,
                        )
                        .unwrap(),
                        e: Integer::try_from_unsigned_bytes(
                            &pk.e().to_bytes_be(),
                            rasn::Codec::Der,
                        )
                        .unwrap(),
                    }
                };

                BitVec::from_vec(encode(&pk).unwrap())
            };

            let akid: OctetString = {
                decode(
                    intermediate_cert
                        .tbs_certificate
                        .extensions
                        .as_ref()
                        .unwrap()
                        .iter()
                        .find(|e| e.extn_id == SUBJECT_KEY_IDENTIFIER)
                        .unwrap()
                        .extn_value
                        .clone()
                        .as_ref(),
                )
                .unwrap()
            };

            let skid = {
                let hash = {
                    let mut hasher = Sha256::new();
                    hasher.update(encode(&subject_public_key).unwrap());
                    hasher.finalize()
                };

                OctetString::from(hash.to_vec())
            };

            let subject_alt_name =
                match Ipv4Addr::from_str(str::from_utf8(ipv4_or_domain_domain).unwrap()) {
                    Ok(ipv4) => SubjectAltName::from([GeneralName::IpAddress(OctetString::from(
                        ipv4.octets(),
                    ))]),
                    Err(_) => SubjectAltName::from([GeneralName::DnsName(
                        Ia5String::from_iso646_bytes(ipv4_or_domain_domain).unwrap(),
                    )]),
                };

            TbsCertificate {
                version: Version::V3,
                serial_number: CertificateSerialNumber::try_from_bytes(
                    &rng.r#gen::<[u8; 16]>(),
                    rasn::Codec::Der,
                )
                .unwrap(),
                signature: AlgorithmIdentifier {
                    algorithm: SHA_256_WITH_RSA_ENCRYPTION,
                    parameters: Some(Any::new(encode(&Null).unwrap())),
                },
                issuer: intermediate_cert.tbs_certificate.subject.clone(),
                validity: validity_now_plus_days(30),
                subject,
                subject_public_key_info: SubjectPublicKeyInfo {
                    algorithm: AlgorithmIdentifier {
                        algorithm: RSA_ENCRYPTION,
                        parameters: Some(Any::new(encode(&Null).unwrap())),
                    },
                    subject_public_key,
                },
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: Some(
                    vec![
                        // If the basic constraints extension is not present in a version 3 certificate,
                        // or the extension is present but the cA boolean is not asserted, then the certified
                        // public key MUST NOT be used to verify certificate signatures.
                        /*
                        Extension {
                            extn_id: BASIC_CONSTRAINTS,
                            critical: true,
                            extn_value: encode(&BasicConstraints {
                                ca: false,
                                path_len_constraint: None,
                            })
                            .unwrap()
                            .into(),
                        },
                        */
                        Extension {
                            extn_id: KEY_USAGE,
                            critical: true,
                            extn_value: OctetString::from(encode(&key_usage).unwrap()),
                        },
                        Extension {
                            extn_id: EXT_KEY_USAGE,
                            critical: false,
                            extn_value: encode(&ExtKeyUsageSyntax::from(&[
                                SERVER_AUTH,
                                CLIENT_AUTH,
                            ]))
                            .unwrap()
                            .into(),
                        },
                        Extension {
                            extn_id: SUBJECT_KEY_IDENTIFIER,
                            critical: false,
                            extn_value: OctetString::from(encode(&skid).unwrap()),
                        },
                        Extension {
                            extn_id: AUTHORITY_KEY_IDENTIFIER,
                            critical: false,
                            extn_value: OctetString::from(
                                encode(&AuthorityKeyIdentifier {
                                    key_identifier: Some(akid),
                                    authority_cert_issuer: None,
                                    authority_cert_serial_number: None,
                                })
                                .unwrap(),
                            ),
                        },
                        // TODO: authorityInfoAccess
                        Extension {
                            extn_id: SUBJECT_ALT_NAME,
                            critical: false,
                            extn_value: OctetString::from(encode(&subject_alt_name).unwrap()),
                        },
                    ]
                    .into(),
                ),
            }
        };

        let signature_algorithm = AlgorithmIdentifier {
            algorithm: SHA_256_WITH_RSA_ENCRYPTION,
            parameters: Some(Any::new(encode(&Null).unwrap())),
        };

        let signature_value = sign_tbs_certificate(&intermediate_key, &tbs_certificate);

        Certificate {
            tbs_certificate,
            signature_algorithm,
            signature_value,
        }
    };

    (sk, cert)
}

fn sign_tbs_certificate(key: &RsaPrivateKey, tbs_certificate: &TbsCertificate) -> BitString {
    let data = {
        let mut prefix =
            b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
                .to_vec();

        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(encode(tbs_certificate).unwrap());
            hasher.finalize()
        };

        prefix.extend_from_slice(&hash);
        prefix
    };

    let signature = key.sign(Pkcs1v15Sign::new_unprefixed(), &data).unwrap();

    BitVec::from_vec(signature)
}

fn validity_now_plus_days(days: i64) -> Validity {
    let now = Local::now();

    Validity {
        not_before: Time::Utc((now.clone() - TimeDelta::minutes(15)).into()),
        // TODO: Is this fine? See <https://en.wikipedia.org/wiki/Year_2038_problem>.
        not_after: Time::General(
            GeneralizedTime::from(now + TimeDelta::days(days))
                .fixed_offset()
                .trunc_subsecs(0),
        ),
    }
}
