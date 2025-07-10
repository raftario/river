pub use boringtun::x25519::{PublicKey, StaticSecret};
use rand::{TryRngCore, rngs::OsRng};

/// Generate a random keypair
pub fn keypair() -> (StaticSecret, PublicKey) {
    let mut secret = [0; 32];
    OsRng.try_fill_bytes(&mut secret).unwrap();

    let secret = StaticSecret::from(secret);
    let public = PublicKey::from(&secret);
    (secret, public)
}
