use argh::FromArgs;
use mkpki::{
    certificate::{gen_intermediate, gen_leaf, gen_root},
    load_cert, load_key, save_cert, save_key, Format,
};
use rand::SeedableRng;
use sha2::Digest;

#[derive(FromArgs, PartialEq, Debug)]
/// mkpki.
struct Arguments {
    #[argh(subcommand)]
    command: Command,
    /// ONLY FOR TESTING: seed CSPRNG with `sha256(argument)`
    #[argh(option)]
    seed: Option<String>,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum Command {
    Root(Root),
    Intermediate(Intermediate),
    Leaf(Leaf),
}

/// Create root certificate.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "root")]
struct Root {
    /// countryName
    #[argh(positional)]
    country_name: String,
    /// organizationName
    #[argh(positional)]
    organization_name: String,
    /// commonName
    #[argh(positional)]
    common_name: String,
}

/// Create intermediate certificate.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "intermediate")]
struct Intermediate {
    /// path to root key
    #[argh(positional)]
    root_key_path: String,
    /// path to root certificate
    #[argh(positional)]
    root_cert_path: String,
    /// countryName
    #[argh(positional)]
    country_name: String,
    /// organizationName
    #[argh(positional)]
    organization_name: String,
    /// commonName
    #[argh(positional)]
    common_name: String,
}

/// Create leaf certificate.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "leaf")]
struct Leaf {
    /// path to intermediate key
    #[argh(positional)]
    intermediate_key_path: String,
    /// path to intermediate certificate
    #[argh(positional)]
    intermediate_cert_path: String,
    /// commonName
    #[argh(positional)]
    common_name: String,
}

fn main() {
    let args: Arguments = argh::from_env();

    let mut rng = match args.seed {
        Some(seed) => {
            rand_chacha::ChaCha8Rng::from_seed(sha2::Sha256::digest(seed.as_bytes()).into())
        }
        None => rand_chacha::ChaCha8Rng::from_entropy(),
    };

    match args.command {
        Command::Root(Root {
            country_name,
            organization_name,
            common_name,
        }) => {
            let (root_key, root_cert) = gen_root(
                &mut rng,
                country_name.as_bytes(),
                organization_name.as_bytes(),
                common_name.as_bytes(),
            );

            save_key(&root_key, Format::Pem, "root-key.pem");
            save_cert(&root_cert, Format::Pem, "root.pem");
        }
        Command::Intermediate(Intermediate {
            root_key_path,
            root_cert_path,
            country_name,
            organization_name,
            common_name,
        }) => {
            let root_key = load_key(Format::Pem, root_key_path);
            let root_cert = load_cert(Format::Pem, root_cert_path);

            let (intermediate_key, intermediate_cert) = gen_intermediate(
                &mut rng,
                &root_key,
                &root_cert,
                country_name.as_bytes(),
                organization_name.as_bytes(),
                common_name.as_bytes(),
            );

            save_key(&intermediate_key, Format::Pem, "intermediate-key.pem");
            save_cert(&intermediate_cert, Format::Pem, "intermediate.pem");
        }
        Command::Leaf(Leaf {
            intermediate_key_path,
            intermediate_cert_path,
            common_name,
        }) => {
            let intermediate_key = load_key(Format::Pem, intermediate_key_path);
            let intermediate_cert = load_cert(Format::Pem, intermediate_cert_path);

            let (leaf_key, leaf_cert) = gen_leaf(
                &mut rng,
                &intermediate_key,
                &intermediate_cert,
                common_name.as_bytes(),
            );

            save_key(&leaf_key, Format::Pem, "leaf-key.pem");
            save_cert(&leaf_cert, Format::Pem, "leaf.pem");
        }
    }
}
