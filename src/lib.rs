pub mod certificate;

use std::{fs::File, io::Write, path::Path};

use pem_rfc7468::LineEnding;
use rand::Rng;
use rasn::der::{decode, encode};
use rasn_pkix::Certificate;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    rand_core::CryptoRng,
    RsaPrivateKey, RsaPublicKey,
};

#[derive(Clone, Copy, Debug)]
pub enum Format {
    Der,
    Pem,
}

pub fn gen_key<R: CryptoRng + Rng>(rng: &mut R, bit_size: usize) -> (RsaPrivateKey, RsaPublicKey) {
    let sk = RsaPrivateKey::new(rng, bit_size).unwrap();
    let pk = sk.to_public_key();
    (sk, pk)
}

pub fn save_key<P: AsRef<Path>>(sk: &RsaPrivateKey, format: Format, path: P) {
    match format {
        Format::Der => {
            unimplemented!()
        }
        Format::Pem => {
            let data = pem_rfc7468::encode_string(
                "PRIVATE KEY",
                LineEnding::LF,
                sk.to_pkcs1_der().unwrap().as_bytes(),
            )
            .unwrap();

            File::create(path)
                .unwrap()
                .write_all(data.as_bytes())
                .unwrap();
        }
    }
}

pub fn load_key<P: AsRef<Path>>(format: Format, path: P) -> RsaPrivateKey {
    match format {
        Format::Der => {
            unimplemented!()
        }
        Format::Pem => {
            let data = std::fs::read(path).unwrap();
            let (type_label, data) = pem_rfc7468::decode_vec(&data).unwrap();
            assert_eq!(type_label, "PRIVATE KEY");
            RsaPrivateKey::from_pkcs1_der(&data).unwrap()
        }
    }
}

pub fn save_cert<P: AsRef<Path>>(cert: &Certificate, format: Format, path: P) {
    match format {
        Format::Der => {
            unimplemented!()
        }
        Format::Pem => {
            let data =
                pem_rfc7468::encode_string("CERTIFICATE", LineEnding::LF, &encode(&cert).unwrap())
                    .unwrap();
            File::create(path)
                .unwrap()
                .write_all(data.as_bytes())
                .unwrap();
        }
    }
}

pub fn load_cert<P: AsRef<Path>>(format: Format, path: P) -> Certificate {
    match format {
        Format::Der => {
            unimplemented!()
        }
        Format::Pem => {
            let data = std::fs::read(path).unwrap();
            let (type_label, data) = pem_rfc7468::decode_vec(&data).unwrap();
            assert_eq!(type_label, "CERTIFICATE");
            decode::<Certificate>(&data).unwrap()
        }
    }
}
