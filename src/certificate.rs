use std::{borrow::Cow, collections::BTreeSet};

use bitvec::prelude::*;
use bytes::Bytes;
use chrono::{Local, TimeDelta};
use num_bigint::Sign;
use num_traits::ops::bytes::FromBytes;
use rand::{CryptoRng, Rng};
use rasn::{
    der::encode,
    types::{Any, BitString, Ia5String, Integer, ObjectIdentifier, Open::Null, PrintableString},
};
use rasn_pkix::{
    AlgorithmIdentifier, AttributeTypeAndValue, AuthorityKeyIdentifier, BasicConstraints,
    Certificate, CertificateSerialNumber, ExtKeyUsageSyntax, Extension, GeneralName,
    GeneralSubtree, Name, NameConstraints, SubjectAltName, SubjectPublicKeyInfo, TbsCertificate,
    Time, Validity, Version,
};
use rsa::{traits::PublicKeyParts, Pkcs1v15Sign, RsaPrivateKey};
use sha2::{Digest, Sha256};

use crate::gen_key;

const COUNTRY_NAME: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 4, 6]));
const ORGANIZATION_NAME: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 4, 10]));
const COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 4, 3]));
const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 29, 15]));
const EXT_KEY_USAGE: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 29, 37]));
const SERVER_AUTH: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 3, 6, 1, 5, 5, 7, 3, 1]));
const CLIENT_AUTH: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 3, 6, 1, 5, 5, 7, 3, 2]));
const BASIC_CONSTRAINTS: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 29, 19]));
const SUBJECT_KEY_IDENTIFIER: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 29, 14]));
const AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 29, 35]));
const SUBJECT_ALT_NAME: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 29, 17]));
const RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 2, 840, 113549, 1, 1, 1]));
const SHA_256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 2, 840, 113549, 1, 1, 11]));
const NAME_CONSTRAINTS: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[2, 5, 29, 30]));

#[derive(Debug, rasn::AsnType, rasn::Encode, rasn::Decode)]
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
            let validity = {
                let now = Local::now();

                Validity {
                    not_before: Time::Utc(now.clone().into()),
                    not_after: Time::Utc((now + TimeDelta::days(25 * 365)).into()),
                }
            };

            let subject = {
                Name::RdnSequence(vec![
                    BTreeSet::from([AttributeTypeAndValue {
                        r#type: COUNTRY_NAME,
                        value: Any::new(
                            encode(&PrintableString::from_bytes(country_name).unwrap()).unwrap(),
                        ),
                    }])
                    .into(),
                    BTreeSet::from([AttributeTypeAndValue {
                        r#type: ORGANIZATION_NAME,
                        value: Any::new(
                            encode(&PrintableString::from_bytes(organization_name).unwrap())
                                .unwrap(),
                        ),
                    }])
                    .into(),
                    BTreeSet::from([AttributeTypeAndValue {
                        r#type: COMMON_NAME,
                        value: Any::new(
                            encode(&PrintableString::from_bytes(common_name).unwrap()).unwrap(),
                        ),
                    }])
                    .into(),
                ])
            };

            let subject_public_key = {
                let pk = {
                    RsaPubKey {
                        n: Integer::from_bytes_be(Sign::Plus, &pk.n().to_bytes_be()),
                        e: Integer::from_bytes_be(Sign::Plus, &pk.e().to_bytes_be()),
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

                Bytes::from(hash.to_vec())
            };

            let key_usage = bitvec![u8, Msb0; 0, 0, 0, 0, 0, 1, 1];

            TbsCertificate {
                version: Version::V3,
                serial_number: CertificateSerialNumber::from_be_bytes(&rng.gen::<[u8; 16]>()),
                signature: AlgorithmIdentifier {
                    algorithm: SHA_256_WITH_RSA_ENCRYPTION,
                    parameters: Some(Any::new(encode(&Null).unwrap())),
                },
                // This certificate is self-signed.
                issuer: subject.clone(),
                validity,
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
                            extn_id: KEY_USAGE,
                            critical: true,
                            extn_value: Bytes::from(encode(&key_usage).unwrap()),
                        },
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
                            extn_id: SUBJECT_KEY_IDENTIFIER,
                            critical: false,
                            extn_value: Bytes::from(encode(&skid).unwrap()),
                        },
                        Extension {
                            extn_id: NAME_CONSTRAINTS,
                            critical: true,
                            extn_value: Bytes::from(
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
) -> (RsaPrivateKey, Certificate) {
    let (sk, pk) = gen_key(rng, 4096);

    let cert = {
        let tbs_certificate = {
            let validity = {
                let now = Local::now();

                Validity {
                    not_before: Time::Utc(now.clone().into()),
                    not_after: Time::Utc((now + TimeDelta::days(25 * 365)).into()),
                }
            };

            let subject = Name::RdnSequence(vec![
                BTreeSet::from([AttributeTypeAndValue {
                    r#type: COUNTRY_NAME,
                    value: Any::new(
                        encode(&PrintableString::from_bytes(country_name).unwrap()).unwrap(),
                    ),
                }])
                .into(),
                BTreeSet::from([AttributeTypeAndValue {
                    r#type: ORGANIZATION_NAME,
                    value: Any::new(
                        encode(&PrintableString::from_bytes(organization_name).unwrap()).unwrap(),
                    ),
                }])
                .into(),
                BTreeSet::from([AttributeTypeAndValue {
                    r#type: COMMON_NAME,
                    value: Any::new(
                        encode(&PrintableString::from_bytes(common_name).unwrap()).unwrap(),
                    ),
                }])
                .into(),
            ]);

            let subject_public_key = {
                let pk = {
                    RsaPubKey {
                        n: Integer::from_bytes_be(Sign::Plus, &pk.n().to_bytes_be()),
                        e: Integer::from_bytes_be(Sign::Plus, &pk.e().to_bytes_be()),
                    }
                };

                BitVec::from_vec(encode(&pk).unwrap())
            };

            let akid = {
                let hash = {
                    let mut hasher = Sha256::new();
                    hasher.update(
                        encode(
                            &root_cert
                                .tbs_certificate
                                .subject_public_key_info
                                .subject_public_key,
                        )
                        .unwrap(),
                    );
                    hasher.finalize()
                };

                Bytes::from(hash.to_vec())
            };

            let skid = {
                let hash = {
                    let mut hasher = Sha256::new();
                    hasher.update(encode(&subject_public_key).unwrap());
                    hasher.finalize()
                };

                Bytes::from(hash.to_vec())
            };

            // TODO: Minimize?
            let key_usage = bitvec![u8, Msb0; 1, 0, 0, 0, 0, 1, 1];

            TbsCertificate {
                version: Version::V3,
                serial_number: CertificateSerialNumber::from_be_bytes(&rng.gen::<[u8; 16]>()),
                signature: AlgorithmIdentifier {
                    algorithm: SHA_256_WITH_RSA_ENCRYPTION,
                    parameters: Some(Any::new(encode(&Null).unwrap())),
                },
                issuer: root_cert.tbs_certificate.subject.clone(),
                validity,
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
                            extn_id: KEY_USAGE,
                            critical: true,
                            extn_value: Bytes::from(encode(&key_usage).unwrap()),
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
                            extn_id: SUBJECT_KEY_IDENTIFIER,
                            critical: false,
                            extn_value: Bytes::from(encode(&skid).unwrap()),
                        },
                        Extension {
                            extn_id: AUTHORITY_KEY_IDENTIFIER,
                            critical: false,
                            extn_value: Bytes::from(
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
                            extn_value: Bytes::from(
                                encode(&NameConstraints {
                                    permitted_subtrees: Some(vec![GeneralSubtree {
                                        base: GeneralName::DnsName(
                                            // TODO
                                            Ia5String::from_iso646_bytes(
                                                b"intermediate.example.org",
                                            )
                                            .unwrap(),
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
    domain: &[u8],
) -> (RsaPrivateKey, Certificate) {
    let (sk, pk) = gen_key(rng, 2048);

    let cert = {
        let tbs_certificate = {
            let validity = {
                let now = Local::now();

                Validity {
                    not_before: Time::Utc(now.clone().into()),
                    not_after: Time::Utc((now + TimeDelta::days(90)).into()),
                }
            };

            let subject = Name::RdnSequence(vec![BTreeSet::from([AttributeTypeAndValue {
                r#type: COMMON_NAME,
                value: Any::new(encode(&PrintableString::from_bytes(domain).unwrap()).unwrap()),
            }])
            .into()]);

            let subject_public_key = {
                let pk = {
                    RsaPubKey {
                        n: Integer::from_bytes_be(Sign::Plus, &pk.n().to_bytes_be()),
                        e: Integer::from_bytes_be(Sign::Plus, &pk.e().to_bytes_be()),
                    }
                };

                BitVec::from_vec(encode(&pk).unwrap())
            };

            let akid = {
                let hash = {
                    let mut hasher = Sha256::new();
                    hasher.update(
                        encode(
                            &intermediate_cert
                                .tbs_certificate
                                .subject_public_key_info
                                .subject_public_key,
                        )
                        .unwrap(),
                    );
                    hasher.finalize()
                };

                Bytes::from(hash.to_vec())
            };

            let skid = {
                let hash = {
                    let mut hasher = Sha256::new();
                    hasher.update(encode(&subject_public_key).unwrap());
                    hasher.finalize()
                };

                Bytes::from(hash.to_vec())
            };

            let key_usage = bitvec![u8, Msb0; 1];

            TbsCertificate {
                version: Version::V3,
                serial_number: CertificateSerialNumber::from_be_bytes(&rng.gen::<[u8; 16]>()),
                signature: AlgorithmIdentifier {
                    algorithm: SHA_256_WITH_RSA_ENCRYPTION,
                    parameters: Some(Any::new(encode(&Null).unwrap())),
                },
                issuer: intermediate_cert.tbs_certificate.subject.clone(),
                validity,
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
                            extn_id: KEY_USAGE,
                            critical: true,
                            extn_value: Bytes::from(encode(&key_usage).unwrap()),
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
                            extn_id: BASIC_CONSTRAINTS,
                            critical: true,
                            extn_value: encode(&BasicConstraints {
                                ca: false,
                                path_len_constraint: None,
                            })
                            .unwrap()
                            .into(),
                        },
                        Extension {
                            extn_id: SUBJECT_KEY_IDENTIFIER,
                            critical: false,
                            extn_value: Bytes::from(encode(&skid).unwrap()),
                        },
                        Extension {
                            extn_id: AUTHORITY_KEY_IDENTIFIER,
                            critical: false,
                            extn_value: Bytes::from(
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
                            extn_value: Bytes::from(
                                encode(&SubjectAltName::from([GeneralName::DnsName(
                                    Ia5String::from_iso646_bytes(domain).unwrap(),
                                )]))
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
