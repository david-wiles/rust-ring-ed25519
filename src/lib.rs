use std::path::Path;

use thiserror::Error;

use ring::rand::SystemRandom;
use ring::pkcs8;
use ring::signature::{ED25519, KeyPair, Ed25519KeyPair, UnparsedPublicKey};

/// Ed25519Engine wraps methods from the ring crate to provide an intuitive API for
/// working with Ed25519 key pairs. This struct only contains the Ed25519KeyPair.
pub struct Ed25519Engine {
    keypair: Ed25519KeyPair,
}

impl Ed25519Engine {
    /// Generate a new ed25519 keypair and save into the specified files. A new
    /// Ed25519Engine is returned on success which has been initialized with the
    /// newly-generated keys. Note that the 'private key' will actually contain
    /// the private and public keys for the keypair.
    ///
    /// # Example: generate, sign, and verify
    ///
    /// ```
    /// use rust_ring_ed25519::Ed25519Engine;
    ///
    /// // Create an engine and save the keys to filesystem for later use
    /// let engine = Ed25519Engine::generate("key.priv", "key.pub").unwrap();
    ///
    /// // Sign some data
    /// let msg = "Hello, World!".as_bytes();
    /// let sig = engine.sign(msg);
    ///
    /// // Verify the signature
    /// let pubkey = engine.public_key();
    /// assert!(pubkey.verify(msg, sig.as_slice()));
    /// ```
    pub fn generate(privkey_file: &str, pubkey_file: &str) -> Result<Self, Error> {
        let doc = random_ed25519();
        let keypair = Ed25519KeyPair::from_pkcs8(doc.as_ref())?;
        std::fs::write(privkey_file, doc.as_ref())?;
        std::fs::write(pubkey_file, keypair.public_key().as_ref())?;
        Ok(Ed25519Engine { keypair })
    }

    /// Generates a new Ed25519Engine for use in-memory. Note that it is not
    /// possible to save the private key when generating a key pair this way, so
    /// this may only be used for applications which don't need to persist the
    /// keypair in storage. It is possible to save the public key or transfer to
    /// a separate system, however.
    ///
    /// # Example: new, sign, and verify
    ///
    /// ```
    /// use rust_ring_ed25519::Ed25519Engine;
    ///
    /// // Create an engine without persisting keys
    /// let engine = Ed25519Engine::new();
    ///
    /// // Sign some data
    /// let msg = "Hello, World!".as_bytes();
    /// let sig = engine.sign(msg);
    ///
    /// // Verify the signature
    /// let pubkey = engine.public_key();
    /// assert!(pubkey.verify(msg, sig.as_slice()));
    /// ```
    pub fn new() -> Self {
        let doc = random_ed25519();
        let keypair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
        Self { keypair }
    }

    /// Loads a keypair from an un-encrypted pkcs8 document saved on the filesystem
    pub fn load(path: &str) -> Result<Self, Error> {
        let p = Path::new(path);
        let bytes = std::fs::read(p)?;
        let keypair = Ed25519KeyPair::from_pkcs8(bytes.as_slice())?;
        Ok(Self { keypair })
    }

    /// Sign the payload bytes using this private key. The signature is returned as a Vec<u8>
    pub fn sign(&self, payload: &[u8]) -> Vec<u8> {
        self.keypair.sign(payload).as_ref().to_owned()
    }

    /// Get the Ed25519PublicKey from this keypair. The public key can be used to verify
    /// signatures which have been signed by this private key and transferred to a different
    /// system for verification of messages.
    ///
    /// # Example: sending a public key to a server to use as an identity key
    ///
    /// ```
    /// use rust_ring_ed25519::Ed25519Engine;
    ///
    /// // Create an engine without persisting keys
    /// let engine = Ed25519Engine::new();
    ///
    /// // Get the public key's bytes to send in HTTPS request
    /// let pubkey = engine.public_key().get_bytes();
    /// // ...
    /// ```
    pub fn public_key(&self) -> Ed25519PublicKey {
        // Copy bytes to a new Vec for Ed25519PublicKey
        Ed25519PublicKey(self.keypair.public_key().as_ref().to_vec())
    }
}

// Generates a new ed25519 keypair using `SystemRandom` in pkcs8 format
fn random_ed25519() -> pkcs8::Document {
    let random = SystemRandom::new();
    Ed25519KeyPair::generate_pkcs8(&random).unwrap()
}

/// Ed25519PublicKey wraps the UnparsedPublicKey methods from the ring crate into a more
/// straightforward interface. This struct is useful for verifying the signature of a
/// message which was signed using the matching private key.
pub struct Ed25519PublicKey(Vec<u8>);

impl Ed25519PublicKey {
    /// Loads the public key from the file. This assumes that the public key has not
    /// used any extra encryption or encoding, and has simply been dumped into the file.
    /// This is compatible with Ed25519Engine::generate, but will not be able to
    /// load public keys created with other cryptographic tools such as openssl.
    pub fn load(path: &str) -> Result<Self, Error> {
        let bytes = std::fs::read(path)?;
        Ok(Self(bytes))
    }

    /// Verify the signature from the message using this public key
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        UnparsedPublicKey::new(&ED25519, self.0.as_slice()).verify(message, signature).is_ok()
    }

    pub fn get_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Cryptographic error")]
    CryptoError(#[from] ring::error::Unspecified),

    #[error("Invalid key")]
    InvalidKey(#[from] ring::error::KeyRejected),

    #[error("IO Error: {0}")]
    StdIO(#[from] std::io::Error),

    #[error("Invalid Encoding")]
    HexDecodeError(#[from] hex::FromHexError),
}

impl From<Error> for String {
    fn from(e: Error) -> Self {
        e.to_string()
    }
}

#[cfg(test)]
mod test {
    use crate::{Ed25519Engine, Ed25519PublicKey};

    #[test]
    fn can_generate_load_sign_verify() {
        // Test setup
        std::fs::create_dir("testkeys").unwrap();
        let msg = "hello world".as_bytes();

        // Generate and save keys
        let engine1 = Ed25519Engine::generate("testkeys/key.priv", "testkeys/key.pub").unwrap();
        let pubkey1 = engine1.public_key();

        // Sign some data
        let sig1 = engine1.sign(msg);

        // Load keys from filesystem
        let engine2 = Ed25519Engine::load("testkeys/key.priv").unwrap();
        let pubkey2 = engine2.public_key();

        // Sign data again
        let sig2 = engine2.sign(msg);

        // Load public key
        let pubkey3 = Ed25519PublicKey::load("testkeys/key.pub").unwrap();

        // Signatures should be equal
        assert_eq!(sig1, sig2);

        // pubkeys should verify sig1 and sig2
        assert!(pubkey1.verify(msg, sig1.as_slice()));
        assert!(pubkey1.verify(msg, sig2.as_slice()));

        assert!(pubkey2.verify(msg, sig1.as_slice()));
        assert!(pubkey2.verify(msg, sig2.as_slice()));

        assert!(pubkey3.verify(msg, sig1.as_slice()));
        assert!(pubkey3.verify(msg, sig2.as_slice()));

        std::fs::remove_dir_all("testkeys").unwrap();
    }
}
