use boringtun::x25519::{PublicKey, StaticSecret};
use rand::rngs::OsRng;

/// Generate a random keypair
pub fn keypair() -> (StaticSecret, PublicKey) {
    let secret = private();
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Generate a random private key
pub fn private() -> StaticSecret {
    StaticSecret::random_from_rng(OsRng)
}
