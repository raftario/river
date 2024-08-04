pub use boringtun::x25519::{PublicKey, StaticSecret};
use rand::rngs::OsRng;

/// Generate a random keypair
pub fn keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}
