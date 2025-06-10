use anyhow::Context;
use x25519_dalek::{PublicKey, StaticSecret};

pub fn identity(private_key: [u8; 32]) -> anyhow::Result<String> {
    let public_key = PublicKey::from(&StaticSecret::from(private_key));

    Ok(format!(
        "# public key: {}\n{}\n",
        bech32_encode("age", public_key.as_bytes())?,
        bech32_encode("AGE-SECRET-KEY-", &private_key)?.to_uppercase(),
    ))
}

fn bech32_encode(hrp: &str, bytes: &[u8]) -> anyhow::Result<String> {
    // let mut data = vec![1]; // version
    // data.extend_from_slice(bytes);

    bech32::encode(
        hrp,
        bech32::ToBase32::to_base32(&bytes),
        bech32::Variant::Bech32,
    )
    .context("bech32::encode")
}
