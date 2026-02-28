use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn verify_signature(headers: &HeaderMap, body: &[u8], secret: &str) -> Result<(), String> {
    let sig_header = headers
        .get("x-topgg-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing x-topgg-signature header")?;

    let mut timestamp = None;
    let mut signature = None;
    for part in sig_header.split(',') {
        if let Some(t) = part.strip_prefix("t=") {
            timestamp = Some(t);
        } else if let Some(v) = part.strip_prefix("v1=") {
            signature = Some(v);
        }
    }

    let timestamp = timestamp.ok_or("missing timestamp in signature")?;
    let signature = signature.ok_or("missing v1 in signature")?;

    let message = format!("{timestamp}.{}", String::from_utf8_lossy(body));
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|e| format!("hmac init: {e}"))?;
    mac.update(message.as_bytes());

    let expected = hex::encode(mac.finalize().into_bytes());

    if !constant_time_eq(expected.as_bytes(), signature.as_bytes()) {
        return Err("signature mismatch".into());
    }

    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}
