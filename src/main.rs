use clap::{Parser, Subcommand};
use rust_ring_ec::{Ed25519Engine, Ed25519PublicKey, Error};


#[derive(Parser)]
#[command(about = "An Ed25519 key tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a random key pair and save with the specified file name
    ///
    /// The private key will be saved with the extension .priv, and
    /// the public key will be saved with the extension .pub.
    /// Note that the format these keys are saved will not be compatible
    /// with other cryptographic tools, such as openssl. For simplicity,
    /// the bytes are dumped to the file unencrypted. This makes the
    /// code more simple to implement and understand, and in the future
    /// may be updated to use traditional formats that may be compatible.
    #[command(verbatim_doc_comment)]
    Generate {
        file: String
    },

    /// Sign the data using the private key located at privkey
    ///
    /// The resulting signature will be printed to stdout with hex-encoding. To
    /// verify that the signature is valid with your public key, use the output
    /// and your message as arguments to 'verify'.
    #[command(verbatim_doc_comment)]
    Sign {
        privkey: String,
        data: String,
    },

    /// Checks the validity of a signature for a given message.
    ///
    /// Using the public key located at pubkey, verify that the signature is valid
    /// for the data. The signature should be hex-encoded. The output of 'sign'
    /// can be used here as the input for sig.
    #[command(verbatim_doc_comment)]
    Verify {
        pubkey: String,
        data: String,
        sig: String,
    },
}

fn generate(file: String) -> Result<String, Error> {
    let priv_filename = file.clone() + ".priv";
    let pub_filename = file + ".pub";
    Ed25519Engine::generate(priv_filename.as_str(), pub_filename.as_str())
        .map(|_| format!("Successfully generated keys in {} and {}", priv_filename, pub_filename))
}

fn sign(privkey: String, data: String) -> Result<String, Error> {
    let engine = Ed25519Engine::load(privkey.as_str())?;
    let sig = engine.sign(data.as_bytes());
    Ok(hex::encode(sig))
}

fn verify(pubkey: String, data: String, sig: String) -> Result<String, Error> {
    let key = Ed25519PublicKey::load(pubkey.as_str())?;
    let decoded_sig = hex::decode(sig)?;

    match key.verify(data.as_bytes(), decoded_sig.as_slice()) {
        true => Ok(String::from("Signature is valid")),
        false => Ok(String::from("Invalid signature"))
    }
}

fn main() {
    let result = match Cli::parse().command {
        Command::Generate { file } => generate(file),
        Command::Sign { privkey, data } => sign(privkey, data),
        Command::Verify { pubkey, data, sig } => verify(pubkey, data, sig)
    };

    match result {
        Ok(msg) => println!("{}", msg),
        Err(err) => eprintln!("{}", err)
    }
}
