use crate::{valid_near_account, Job};
use bs58::decode;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// 1Click manager key from `@defuse-protocol/one-click-sdk-typescript` 0.1.26.
const ONE_CLICK_MANAGER_PUB_KEY: &str = "reYaWhvwu8Jzo3WUM3zhn6VrhuMEF4eADL17qtRVifc";
const ORIGIN: &str = "nep141:wrap.near";
const DESTINATION: &str = "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near";

#[derive(Debug)]
pub struct BoundQuote {
    pub deposit_account: String,
    pub memo: Option<String>,
}

/// The payload is the canonical JSON 1Click signed. A different destination breaks the signature.
pub fn bind_quote(payload: &str, signature: &str, job: &Job) -> Result<BoundQuote, &'static str> {
    verify_signature(payload, signature, ONE_CLICK_MANAGER_PUB_KEY)?;
    bind_verified_payload(payload, job)
}

fn bind_verified_payload(payload: &str, job: &Job) -> Result<BoundQuote, &'static str> {
    let value: Value = serde_json::from_str(payload).map_err(|_| "payload is not json")?;
    if value.get("dry").and_then(Value::as_bool) != Some(false) {
        return Err("dry quote");
    }
    let recipient = text(&value, "recipient")?;
    let amount_in = text(&value, "amountIn")?;
    let amount_out = text(&value, "amountOut")?;
    let deposit = text(&value, "depositAddress")?;
    if !recipient.eq_ignore_ascii_case(&job.base_recipient) {
        return Err("recipient mismatch");
    }
    if amount_in != job.amount.to_string() {
        return Err("amount mismatch");
    }
    if amount_out != job.amount_out {
        return Err("amount out mismatch");
    }
    if text(&value, "originAsset")? != ORIGIN {
        return Err("origin mismatch");
    }
    if text(&value, "destinationAsset")? != DESTINATION {
        return Err("destination mismatch");
    }
    if !valid_near_account(deposit) {
        return Err("bad deposit account");
    }
    let memo = value.get("depositMemo").and_then(Value::as_str).map(str::to_string);
    Ok(BoundQuote { deposit_account: deposit.to_string(), memo })
}

fn verify_signature(payload: &str, signature: &str, public_key: &str) -> Result<(), &'static str> {
    let signature = decode_key(signature, 64)?;
    let public_key = decode_key(public_key, 32)?;
    let hash = Sha256::digest(payload.as_bytes());
    let message = bs58::encode(hash).into_string();
    let key = VerifyingKey::from_bytes(&public_key).map_err(|_| "bad public key")?;
    let signature = Signature::from_bytes(&signature);
    key.verify(message.as_bytes(), &signature).map_err(|_| "bad quote signature")
}

fn decode_key<const N: usize>(value: &str, expected: usize) -> Result<[u8; N], &'static str> {
    let encoded = value.strip_prefix("ed25519:").unwrap_or(value);
    let bytes = decode(encoded).into_vec().map_err(|_| "bad base58")?;
    if bytes.len() != expected {
        return Err("bad key length");
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    value.get(key).and_then(Value::as_str).ok_or("quote field missing")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Desk, JobState};
    use ed25519_dalek::{Signer, SigningKey};

    const POSTER: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
    const ONE: u128 = 1_000_000_000_000_000_000_000_000;
    const DEPOSIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn job() -> crate::Job {
        let mut desk = Desk::new("owner.testnet");
        desk.fund("owner.testnet", 2 * ONE).unwrap();
        desk.set_cap("owner.testnet", "agent.testnet", 2 * ONE).unwrap();
        desk.hire("agent.testnet", POSTER, ONE, "1171691").unwrap();
        desk.jobs[&0].clone()
    }

    fn payload() -> String {
        format!(
            r#"{{"amountIn":"{ONE}","amountOut":"1171691","depositAddress":"{DEPOSIT}","destinationAsset":"{DESTINATION}","dry":false,"originAsset":"{ORIGIN}","recipient":"{POSTER}"}}"#
        )
    }

    fn sign(payload: &str, secret: &[u8; 32]) -> String {
        let hash = Sha256::digest(payload.as_bytes());
        let message = bs58::encode(hash).into_string();
        let key = SigningKey::from_bytes(secret);
        let signature = key.sign(message.as_bytes());
        format!("ed25519:{}", bs58::encode(signature.to_bytes()).into_string())
    }

    #[test]
    fn signed_quote_binds_the_deposit_account() {
        let secret = [7u8; 32];
        let key = SigningKey::from_bytes(&secret);
        let public_key = bs58::encode(key.verifying_key().to_bytes()).into_string();
        let body = payload();
        let signature = sign(&body, &secret);
        verify_signature(&body, &signature, &public_key).unwrap();
        let bound = bind_verified_payload(&body, &job()).unwrap();
        assert_eq!(bound.deposit_account, DEPOSIT);
        assert_eq!(job().state, JobState::Open);
    }

    #[test]
    fn tampered_recipient_fails_the_field_check() {
        let mut body = payload();
        body = body.replace(POSTER, "0x0000000000000000000000000000000000000001");
        let err = bind_verified_payload(&body, &job()).unwrap_err();
        assert_eq!(err, "recipient mismatch");
    }

    #[test]
    fn tampered_bytes_fail_the_signature() {
        let secret = [7u8; 32];
        let key = SigningKey::from_bytes(&secret);
        let public_key = bs58::encode(key.verifying_key().to_bytes()).into_string();
        let body = payload();
        let signature = sign(&body, &secret);
        let tampered = body.replace(DEPOSIT, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert_eq!(verify_signature(&tampered, &signature, &public_key), Err("bad quote signature"));
    }

    #[test]
    fn live_one_click_quote_binds_its_deposit_account() {
        let fixture: Value = serde_json::from_str(include_str!("../testdata/live-quote.json")).unwrap();
        let payload = fixture["payload"].as_str().unwrap();
        let signature = fixture["signature"].as_str().unwrap();
        let amount: u128 = fixture["amount"].as_str().unwrap().parse().unwrap();
        let amount_out = fixture["amountOut"].as_str().unwrap();
        let recipient = fixture["recipient"].as_str().unwrap();
        let mut desk = Desk::new("owner.near");
        desk.fund("owner.near", amount).unwrap();
        desk.set_cap("owner.near", "agent.near", amount).unwrap();
        desk.hire("agent.near", recipient, amount, amount_out).unwrap();
        let job = desk.jobs[&0].clone();
        let bound = bind_quote(payload, signature, &job).unwrap();
        assert_eq!(bound.deposit_account, fixture["depositAddress"].as_str().unwrap());

        let mut other = job.clone();
        other.amount_out = "1".to_string();
        assert_eq!(bind_quote(payload, signature, &other).unwrap_err(), "amount out mismatch");
    }
}
