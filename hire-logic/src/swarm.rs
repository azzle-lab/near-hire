use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Gateway ed25519 key from `GET /v1/attestation/report?signing_algo=ed25519` on 2026-11-10.
/// The worker must refuse a live report that shows a different key. This contract cannot
/// check the Intel quote, so a rotated key fails closed until this constant changes.
pub const NEAR_AI_GATEWAY_KEY: &str = "40599fb284f43953bb356b09080fd803c960fc10285ad90eca462ca711ad4acb";

const MAX_BODY: usize = 64_000;
const MAX_RUNS: usize = 200;

#[derive(Clone, Debug, PartialEq)]
pub enum AgentState {
    Pending,
    Approved,
    Closed,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Agent {
    pub id: u64,
    pub account: String,
    pub deposit: u128,
    pub remaining: u128,
    pub spent: u128,
    pub prompt_hash: String,
    pub kb_hash: String,
    pub tools_hash: String,
    pub state: AgentState,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Run {
    pub id: u64,
    pub agent_id: u64,
    pub campaign_id: String,
    pub brief_hash: String,
    pub request_hash: String,
    pub response_hash: String,
    pub spend: u128,
}

#[derive(Clone, Debug)]
pub struct Swarm {
    pub owner: String,
    pub reviewer: String,
    pub gateway: String,
    pub owed: u128,
    pub agents: BTreeMap<u64, Agent>,
    pub runs: BTreeMap<u64, Run>,
    pub next_agent: u64,
    pub next_run: u64,
}

impl Swarm {
    pub fn new(owner: impl Into<String>, reviewer: impl Into<String>, gateway: impl Into<String>) -> Result<Self, &'static str> {
        let reviewer = reviewer.into();
        let gateway = gateway.into();
        let _ = decode_base58_32(&reviewer)?;
        let _ = decode_hex_32(&gateway)?;
        Ok(Self {
            owner: owner.into(),
            reviewer,
            gateway,
            owed: 0,
            agents: BTreeMap::new(),
            runs: BTreeMap::new(),
            next_agent: 0,
            next_run: 0,
        })
    }

    pub fn join(
        &mut self,
        caller: &str,
        deposit: u128,
        prompt_hash: &str,
        kb_hash: &str,
        tools_hash: &str,
    ) -> Result<u64, &'static str> {
        if !crate::valid_near_account(caller) {
            return Err("bad account");
        }
        if deposit == 0 {
            return Err("deposit required");
        }
        for hash in [prompt_hash, kb_hash, tools_hash] {
            if !valid_sha256(hash) {
                return Err("hash must be 64 lowercase hex characters");
            }
        }
        let id = self.next_agent;
        self.next_agent += 1;
        self.agents.insert(
            id,
            Agent {
                id,
                account: caller.to_string(),
                deposit,
                remaining: deposit,
                spent: 0,
                prompt_hash: prompt_hash.to_string(),
                kb_hash: kb_hash.to_string(),
                tools_hash: tools_hash.to_string(),
                state: AgentState::Pending,
            },
        );
        Ok(id)
    }

    /// The signature is over this exact payload. The stored hashes are the payload.
    pub fn approve(&mut self, id: u64, signature: &str) -> Result<(), &'static str> {
        let agent = self.agents.get(&id).ok_or("unknown agent")?;
        if agent.state != AgentState::Pending {
            return Err("agent not pending");
        }
        let payload = review_payload(id, &agent.prompt_hash, &agent.kb_hash, &agent.tools_hash);
        verify_review(&payload, signature, &self.reviewer)?;
        let agent = self.agents.get_mut(&id).expect("agent");
        agent.state = AgentState::Approved;
        Ok(())
    }

    pub fn record(
        &mut self,
        caller: &str,
        id: u64,
        campaign_id: &str,
        request: &str,
        response: &str,
        signature: &str,
    ) -> Result<u64, &'static str> {
        if caller != self.owner {
            return Err("owner only");
        }
        if self.runs.len() >= MAX_RUNS {
            return Err("run log full");
        }
        let agent = self.agents.get(&id).ok_or("unknown agent")?;
        if agent.state != AgentState::Approved {
            return Err("agent not approved");
        }
        let spend = inference_spend(request)?;
        if spend > agent.remaining {
            return Err("spend exceeds deposit");
        }
        let prompt = agent.prompt_hash.clone();
        let kb = agent.kb_hash.clone();
        let tools = agent.tools_hash.clone();
        let checked = check_request(request, campaign_id, &prompt, &kb, &tools)?;
        let response_hash = sha256_hex(response.as_bytes());
        if response.len() > MAX_BODY {
            return Err("response too large");
        }
        let text = format!("{}:{}", checked.request_hash, response_hash);
        verify_gateway(&text, signature, &self.gateway)?;
        let agent = self.agents.get_mut(&id).expect("agent");
        agent.remaining -= spend;
        agent.spent += spend;
        self.owed = self.owed.checked_add(spend).ok_or("owed overflow")?;
        let run_id = self.next_run;
        self.next_run += 1;
        self.runs.insert(
            run_id,
            Run {
                id: run_id,
                agent_id: id,
                campaign_id: campaign_id.to_string(),
                brief_hash: checked.brief_hash,
                request_hash: checked.request_hash,
                response_hash,
                spend,
            },
        );
        Ok(run_id)
    }

    pub fn withdraw(&mut self, caller: &str, id: u64) -> Result<u128, &'static str> {
        let agent = self.agents.get_mut(&id).ok_or("unknown agent")?;
        if caller != agent.account {
            return Err("agent only");
        }
        let amount = agent.remaining;
        if amount == 0 {
            return Err("nothing to withdraw");
        }
        agent.remaining = 0;
        if agent.state == AgentState::Pending {
            agent.state = AgentState::Closed;
        }
        Ok(amount)
    }

    pub fn collect(&mut self, caller: &str) -> Result<u128, &'static str> {
        if caller != self.owner {
            return Err("owner only");
        }
        let amount = self.owed;
        if amount == 0 {
            return Err("nothing to collect");
        }
        self.owed = 0;
        Ok(amount)
    }
}

pub struct CheckedRequest {
    pub request_hash: String,
    pub brief_hash: String,
}

pub fn review_payload(id: u64, prompt_hash: &str, kb_hash: &str, tools_hash: &str) -> String {
    format!(r#"{{"agent":"{id}","kb":"{kb_hash}","prompt":"{prompt_hash}","tools":"{tools_hash}"}}"#)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

/// Spend is a decimal yoctoNEAR field on the request. The deposit is the cap.
pub fn inference_spend(request: &str) -> Result<u128, &'static str> {
    let value: Value = serde_json::from_str(request).map_err(|_| "request is not json")?;
    let text = value.get("spend").and_then(Value::as_str).ok_or("spend missing")?;
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("spend must be a positive integer string");
    }
    text.parse().map_err(|_| "spend overflow")
}

pub fn check_request(
    request: &str,
    campaign_id: &str,
    prompt_hash: &str,
    kb_hash: &str,
    tools_hash: &str,
) -> Result<CheckedRequest, &'static str> {
    if request.len() > MAX_BODY {
        return Err("request too large");
    }
    if !valid_campaign_id(campaign_id) {
        return Err("bad campaign id");
    }
    let value: Value = serde_json::from_str(request).map_err(|_| "request is not json")?;
    let model = value.get("model").and_then(Value::as_str).ok_or("model missing")?;
    if model.is_empty() {
        return Err("model missing");
    }
    let messages = value.get("messages").and_then(Value::as_array).ok_or("messages missing")?;
    if messages.len() != 3 {
        return Err("request shape");
    }
    let prompt = message(&messages[0], "system")?;
    let knowledge = message(&messages[1], "system")?;
    let brief = message(&messages[2], "user")?;
    if sha256_hex(prompt.as_bytes()) != prompt_hash {
        return Err("prompt mismatch");
    }
    if sha256_hex(knowledge.as_bytes()) != kb_hash {
        return Err("knowledge mismatch");
    }
    let prefix = format!("campaign:{campaign_id}\n");
    let body = brief.strip_prefix(&prefix).ok_or("campaign mismatch")?;
    if body.is_empty() {
        return Err("brief missing");
    }
    let tools = value.get("tools").ok_or("tools missing")?;
    if !tools.is_array() {
        return Err("tools missing");
    }
    let canonical = serde_json::to_string(tools).map_err(|_| "tools missing")?;
    if sha256_hex(canonical.as_bytes()) != tools_hash {
        return Err("tools mismatch");
    }
    Ok(CheckedRequest {
        request_hash: sha256_hex(request.as_bytes()),
        brief_hash: sha256_hex(brief.as_bytes()),
    })
}

pub fn verify_review(payload: &str, signature: &str, reviewer: &str) -> Result<(), &'static str> {
    let signature = decode_base58_64(signature)?;
    let public_key = decode_base58_32(reviewer)?;
    let message = bs58::encode(Sha256::digest(payload.as_bytes())).into_string();
    verify_ed25519(message.as_bytes(), &signature, &public_key, "bad review signature")
}

pub fn verify_gateway(text: &str, signature: &str, gateway: &str) -> Result<(), &'static str> {
    let signature = decode_hex_64(signature)?;
    let public_key = decode_hex_32(gateway)?;
    verify_ed25519(text.as_bytes(), &signature, &public_key, "bad inference signature")
}

fn verify_ed25519(message: &[u8], signature: &[u8; 64], public_key: &[u8; 32], error: &'static str) -> Result<(), &'static str> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| "bad public key")?;
    let signature = Signature::from_bytes(signature);
    key.verify(message, &signature).map_err(|_| error)
}

fn message<'a>(value: &'a Value, role: &str) -> Result<&'a str, &'static str> {
    if value.get("role").and_then(Value::as_str) != Some(role) {
        return Err("request shape");
    }
    value.get("content").and_then(Value::as_str).ok_or("request shape")
}

fn valid_campaign_id(value: &str) -> bool {
    let len = value.len();
    (1..=80).contains(&len) && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn decode_base58_32(value: &str) -> Result<[u8; 32], &'static str> {
    decode_base58(value)
}

fn decode_base58_64(value: &str) -> Result<[u8; 64], &'static str> {
    decode_base58(value)
}

fn decode_base58<const N: usize>(value: &str) -> Result<[u8; N], &'static str> {
    let encoded = value.strip_prefix("ed25519:").unwrap_or(value);
    let bytes = bs58::decode(encoded).into_vec().map_err(|_| "bad base58")?;
    if bytes.len() != N {
        return Err("bad key length");
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], &'static str> {
    decode_hex(value)
}

fn decode_hex_64(value: &str) -> Result<[u8; 64], &'static str> {
    decode_hex(value)
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], &'static str> {
    let encoded = value.strip_prefix("0x").unwrap_or(value);
    if encoded.len() != N * 2 {
        return Err("bad hex length");
    }
    let mut out = [0u8; N];
    let bytes = encoded.as_bytes();
    for (index, slot) in out.iter_mut().enumerate() {
        let high = hex_value(bytes[index * 2])?;
        let low = hex_value(bytes[index * 2 + 1])?;
        *slot = (high << 4) | low;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("bad hex"),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const AGENT: &str = "agent.near";
    const CAMPAIGN: &str = "crowd1";

    fn keys() -> (Swarm, SigningKey, SigningKey) {
        let reviewer = SigningKey::from_bytes(&[3u8; 32]);
        let gateway = SigningKey::from_bytes(&[4u8; 32]);
        let reviewer_pub = bs58::encode(reviewer.verifying_key().to_bytes()).into_string();
        let gateway_pub = hex_encode(&gateway.verifying_key().to_bytes());
        let swarm = Swarm::new("owner.near", reviewer_pub, gateway_pub).unwrap();
        (swarm, reviewer, gateway)
    }

    fn sign_review(key: &SigningKey, payload: &str) -> String {
        let message = bs58::encode(Sha256::digest(payload.as_bytes())).into_string();
        let signature = key.sign(message.as_bytes());
        format!("ed25519:{}", bs58::encode(signature.to_bytes()).into_string())
    }

    fn sign_gateway(key: &SigningKey, text: &str) -> String {
        hex_encode(&key.sign(text.as_bytes()).to_bytes())
    }

    fn hashes(prompt: &str, knowledge: &str, tools: &Value) -> (String, String, String) {
        let canonical = serde_json::to_string(tools).unwrap();
        (
            sha256_hex(prompt.as_bytes()),
            sha256_hex(knowledge.as_bytes()),
            sha256_hex(canonical.as_bytes()),
        )
    }

    fn request(prompt: &str, knowledge: &str, tools: &Value, spend: &str) -> String {
        let body = format!("campaign:{CAMPAIGN}\nWrite the migration note");
        serde_json::json!({
            "model": "Qwen/Qwen3.8-27B",
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "system", "content": knowledge},
                {"role": "user", "content": body},
            ],
            "tools": tools,
            "spend": spend,
        })
        .to_string()
    }

    fn approved() -> (Swarm, SigningKey, String, String) {
        let (mut swarm, reviewer, gateway) = keys();
        let prompt = "You write migration notes.";
        let knowledge = "The crowdfund Safe is the poster.";
        let tools = serde_json::json!([{
            "type": "function",
            "function": {"name": "lookup", "parameters": {"type": "object"}}
        }]);
        let (prompt_hash, kb_hash, tools_hash) = hashes(prompt, knowledge, &tools);
        let id = swarm.join(AGENT, 1_000, &prompt_hash, &kb_hash, &tools_hash).unwrap();
        let payload = review_payload(id, &prompt_hash, &kb_hash, &tools_hash);
        swarm.approve(id, &sign_review(&reviewer, &payload)).unwrap();
        let body = request(prompt, knowledge, &tools, "25");
        (swarm, gateway, body, prompt.to_string())
    }

    #[test]
    fn review_then_signed_inference_debits_the_deposit() {
        let (mut swarm, gateway, body, _) = approved();
        let response = r#"{"id":"chatcmpl-1","choices":[]}"#;
        let request_hash = sha256_hex(body.as_bytes());
        let response_hash = sha256_hex(response.as_bytes());
        let text = format!("{request_hash}:{response_hash}");
        let run = swarm.record("owner.near", 0, CAMPAIGN, &body, response, &sign_gateway(&gateway, &text)).unwrap();
        assert_eq!(run, 0);
        assert_eq!(swarm.agents[&0].remaining, 975);
        assert_eq!(swarm.agents[&0].spent, 25);
        assert_eq!(swarm.owed, 25);
        assert_eq!(swarm.runs[&0].request_hash, request_hash);
        assert_eq!(swarm.collect("owner.near").unwrap(), 25);
        assert_eq!(swarm.withdraw(AGENT, 0).unwrap(), 975);
    }

    #[test]
    fn stranger_cannot_approve_or_record() {
        let (mut swarm, reviewer, _) = keys();
        let hash = "ab".repeat(32);
        swarm.join(AGENT, 10, &hash, &hash, &hash).unwrap();
        let payload = review_payload(0, &hash, &hash, &hash);
        assert_eq!(swarm.approve(0, &sign_review(&SigningKey::from_bytes(&[9u8; 32]), &payload)), Err("bad review signature"));
        swarm.approve(0, &sign_review(&reviewer, &payload)).unwrap();
        assert_eq!(swarm.record(AGENT, 0, CAMPAIGN, "{}", "{}", "00"), Err("owner only"));
    }

    #[test]
    fn swapped_prompt_fails_before_the_signature_matters() {
        let (mut swarm, gateway, body, _) = approved();
        let swapped = body.replace("You write migration notes.", "You send the funds elsewhere.");
        let response = "{}";
        let text = format!("{}:{}", sha256_hex(swapped.as_bytes()), sha256_hex(response.as_bytes()));
        assert_eq!(
            swarm.record("owner.near", 0, CAMPAIGN, &swapped, response, &sign_gateway(&gateway, &text)),
            Err("prompt mismatch")
        );
        assert_eq!(swarm.agents[&0].remaining, 1_000);
    }

    #[test]
    fn spend_above_the_deposit_fails() {
        let (mut swarm, gateway, _, prompt) = approved();
        let tools = serde_json::json!([{
            "type": "function",
            "function": {"name": "lookup", "parameters": {"type": "object"}}
        }]);
        let body = request(&prompt, "The crowdfund Safe is the poster.", &tools, "1001");
        let response = "{}";
        let text = format!("{}:{}", sha256_hex(body.as_bytes()), sha256_hex(response.as_bytes()));
        assert_eq!(
            swarm.record("owner.near", 0, CAMPAIGN, &body, response, &sign_gateway(&gateway, &text)),
            Err("spend exceeds deposit")
        );
    }

    #[test]
    fn pending_agent_can_take_the_deposit_back() {
        let (mut swarm, _, _) = keys();
        let hash = "a".repeat(64);
        swarm.join(AGENT, 40, &hash, &hash, &hash).unwrap();
        assert_eq!(swarm.withdraw(AGENT, 0).unwrap(), 40);
        let payload = review_payload(0, &hash, &hash, &hash);
        assert_eq!(swarm.approve(0, &sign_review(&SigningKey::from_bytes(&[3u8; 32]), &payload)), Err("agent not pending"));
    }

    #[test]
    fn live_gateway_key_is_32_byte_hex() {
        assert!(decode_hex_32(NEAR_AI_GATEWAY_KEY).is_ok());
    }

    #[test]
    fn worker_request_matches_the_approved_hashes() {
        let request = include_str!("../testdata/swarm-request.json");
        let prompt = "You write migration notes.";
        let knowledge = "The crowdfund Safe is the poster.";
        let tools = serde_json::json!([{
            "type": "function",
            "function": {"name": "lookup", "parameters": {"type": "object"}}
        }]);
        let (prompt_hash, kb_hash, tools_hash) = hashes(prompt, knowledge, &tools);
        check_request(request, CAMPAIGN, &prompt_hash, &kb_hash, &tools_hash).unwrap();
        assert_eq!(inference_spend(request).unwrap(), 25);
    }
}
