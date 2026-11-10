mod quote;
pub mod swarm;

use std::collections::BTreeMap;

pub use quote::bind_quote;

#[derive(Clone, PartialEq, Debug)]
pub enum JobState {
    Open,
    Releasing,
    Released,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Job {
    pub id: u64,
    pub hirer: String,
    pub amount: u128,
    pub base_recipient: String,
    pub amount_out: String,
    pub state: JobState,
    pub deposit_account: Option<String>,
    pub memo: Option<String>,
}

/// Owner-funded treasury. `hire` reserves NEAR. It does not send it.
#[derive(Clone, Debug)]
pub struct Desk {
    pub owner: String,
    pub available: u128,
    pub reserved: u128,
    pub caps: BTreeMap<String, u128>,
    pub jobs: BTreeMap<u64, Job>,
    pub next_id: u64,
}

impl Desk {
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            owner: owner.into(),
            available: 0,
            reserved: 0,
            caps: BTreeMap::new(),
            jobs: BTreeMap::new(),
            next_id: 0,
        }
    }

    pub fn fund(&mut self, caller: &str, amount: u128) -> Result<(), &'static str> {
        self.only_owner(caller)?;
        if amount == 0 {
            return Err("deposit required");
        }
        self.available = self.available.checked_add(amount).ok_or("available overflow")?;
        Ok(())
    }

    pub fn set_cap(&mut self, caller: &str, agent: &str, cap: u128) -> Result<(), &'static str> {
        self.only_owner(caller)?;
        self.caps.insert(agent.to_string(), cap);
        Ok(())
    }

    pub fn hire(
        &mut self,
        caller: &str,
        base_recipient: &str,
        amount: u128,
        amount_out: &str,
    ) -> Result<u64, &'static str> {
        if amount == 0 {
            return Err("amount required");
        }
        if !valid_base_recipient(base_recipient) {
            return Err("base recipient must be 0x and 40 hex");
        }
        if !valid_amount_out(amount_out) {
            return Err("amount out must be a positive integer string");
        }
        let cap = self.caps.get(caller).copied().unwrap_or(0);
        if amount > cap {
            return Err("amount exceeds cap");
        }
        if amount > self.available {
            return Err("amount exceeds available");
        }
        self.caps.insert(caller.to_string(), cap - amount);
        self.available -= amount;
        self.reserved = self.reserved.checked_add(amount).ok_or("reserved overflow")?;
        let id = self.next_id;
        self.next_id += 1;
        self.jobs.insert(
            id,
            Job {
                id,
                hirer: caller.to_string(),
                amount,
                base_recipient: base_recipient.to_string(),
                amount_out: amount_out.to_string(),
                state: JobState::Open,
                deposit_account: None,
                memo: None,
            },
        );
        Ok(id)
    }

    pub fn cancel(&mut self, caller: &str, id: u64) -> Result<(), &'static str> {
        let job = self.jobs.get(&id).ok_or("unknown job")?;
        if caller != job.hirer && caller != self.owner {
            return Err("only hirer or owner");
        }
        if job.state != JobState::Open {
            return Err("job not open");
        }
        let hirer = job.hirer.clone();
        let amount = job.amount;
        self.restore(&hirer, amount)?;
        let job = self.jobs.get_mut(&id).expect("job");
        job.state = JobState::Cancelled;
        Ok(())
    }

    /// Hirer or owner. Locks the job and records the only account that may receive the wNEAR.
    pub fn begin_release(
        &mut self,
        caller: &str,
        id: u64,
        deposit_account: &str,
        memo: Option<&str>,
    ) -> Result<u128, &'static str> {
        if !valid_near_account(deposit_account) {
            return Err("bad deposit account");
        }
        let job = self.jobs.get_mut(&id).ok_or("unknown job")?;
        if caller != job.hirer && caller != self.owner {
            return Err("only hirer or owner");
        }
        if job.state != JobState::Open {
            return Err("job not open");
        }
        let amount = job.amount;
        job.state = JobState::Releasing;
        job.deposit_account = Some(deposit_account.to_string());
        job.memo = memo.map(str::to_string);
        Ok(amount)
    }

    pub fn finish_release(&mut self, id: u64) -> Result<(), &'static str> {
        let job = self.jobs.get_mut(&id).ok_or("unknown job")?;
        if job.state != JobState::Releasing {
            return Err("job not releasing");
        }
        let amount = job.amount;
        job.state = JobState::Released;
        self.reserved -= amount;
        Ok(())
    }

    pub fn abort_release(&mut self, caller: &str, id: u64) -> Result<(), &'static str> {
        self.only_owner(caller)?;
        let job = self.jobs.get_mut(&id).ok_or("unknown job")?;
        if job.state != JobState::Releasing {
            return Err("job not releasing");
        }
        job.state = JobState::Open;
        Ok(())
    }

    pub fn withdraw(&mut self, caller: &str, amount: u128) -> Result<(), &'static str> {
        self.only_owner(caller)?;
        if amount == 0 {
            return Err("amount required");
        }
        if amount > self.available {
            return Err("amount exceeds available");
        }
        self.available -= amount;
        Ok(())
    }

    fn only_owner(&self, caller: &str) -> Result<(), &'static str> {
        if caller == self.owner {
            Ok(())
        } else {
            Err("owner only")
        }
    }

    fn restore(&mut self, hirer: &str, amount: u128) -> Result<(), &'static str> {
        let cap = self.caps.get(hirer).copied().unwrap_or(0);
        self.caps.insert(hirer.to_string(), cap.checked_add(amount).ok_or("cap overflow")?);
        self.reserved -= amount;
        self.available = self.available.checked_add(amount).ok_or("available overflow")?;
        Ok(())
    }
}

pub fn valid_base_recipient(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("0x") else {
        return false;
    };
    hex.len() == 40 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn valid_near_account(value: &str) -> bool {
    let len = value.len();
    if !(2..=64).contains(&len) || !value.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_' || byte == b'.') {
        return false;
    }
    !value.starts_with('.') && !value.ends_with('.') && !value.contains("..")
}

pub fn valid_amount_out(value: &str) -> bool {
    !value.is_empty() && value != "0" && value.len() <= 40 && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "owner.testnet";
    const AGENT: &str = "agent.testnet";
    const POSTER: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
    const ONE: u128 = 1_000_000_000_000_000_000_000_000;
    const DEPOSIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn setup() -> Desk {
        let mut desk = Desk::new(OWNER);
        desk.fund(OWNER, 10 * ONE).unwrap();
        desk.set_cap(OWNER, AGENT, 2 * ONE).unwrap();
        desk
    }

    #[test]
    fn hire_reserves_and_reduces_cap() {
        let mut desk = setup();
        let id = desk.hire(AGENT, POSTER, ONE, "464566").unwrap();
        assert_eq!(id, 0);
        assert_eq!(desk.available, 9 * ONE);
        assert_eq!(desk.reserved, ONE);
        assert_eq!(desk.caps[AGENT], ONE);
        let job = &desk.jobs[&0];
        assert_eq!(job.state, JobState::Open);
        assert_eq!(job.base_recipient, POSTER);
        assert_eq!(job.amount_out, "464566");
    }

    #[test]
    fn hire_over_cap() {
        let mut desk = setup();
        assert_eq!(desk.hire(AGENT, POSTER, 3 * ONE, "1"), Err("amount exceeds cap"));
    }

    #[test]
    fn hire_over_treasury() {
        let mut desk = setup();
        desk.set_cap(OWNER, AGENT, 100 * ONE).unwrap();
        assert_eq!(desk.hire(AGENT, POSTER, 11 * ONE, "1"), Err("amount exceeds available"));
    }

    #[test]
    fn hire_rejects_bad_recipient() {
        let mut desk = setup();
        assert_eq!(
            desk.hire(AGENT, "not-an-address", ONE, "1"),
            Err("base recipient must be 0x and 40 hex")
        );
    }

    #[test]
    fn agent_cannot_withdraw_fund_or_set_cap() {
        let mut desk = setup();
        assert_eq!(desk.withdraw(AGENT, ONE), Err("owner only"));
        assert_eq!(desk.fund(AGENT, ONE), Err("owner only"));
        assert_eq!(desk.set_cap(AGENT, AGENT, ONE), Err("owner only"));
    }

    #[test]
    fn agent_release_records_the_deposit_account() {
        let mut desk = setup();
        desk.hire(AGENT, POSTER, ONE, "464566").unwrap();
        assert_eq!(desk.begin_release(AGENT, 0, DEPOSIT, None).unwrap(), ONE);
        assert_eq!(desk.jobs[&0].deposit_account.as_deref(), Some(DEPOSIT));
        assert_eq!(desk.jobs[&0].state, JobState::Releasing);
    }

    #[test]
    fn stranger_cannot_release() {
        let mut desk = setup();
        desk.hire(AGENT, POSTER, ONE, "1").unwrap();
        assert_eq!(desk.begin_release("other.testnet", 0, DEPOSIT, None), Err("only hirer or owner"));
    }

    #[test]
    fn cancel_restores_cap_and_treasury() {
        let mut desk = setup();
        desk.hire(AGENT, POSTER, ONE, "464566").unwrap();
        desk.cancel(AGENT, 0).unwrap();
        assert_eq!(desk.jobs[&0].state, JobState::Cancelled);
        assert_eq!(desk.available, 10 * ONE);
        assert_eq!(desk.reserved, 0);
        assert_eq!(desk.caps[AGENT], 2 * ONE);
    }

    #[test]
    fn release_marks_job_and_leaves_the_rest_available() {
        let mut desk = setup();
        desk.hire(AGENT, POSTER, ONE, "464566").unwrap();
        assert_eq!(desk.begin_release(AGENT, 0, DEPOSIT, None).unwrap(), ONE);
        assert_eq!(desk.jobs[&0].state, JobState::Releasing);
        assert_eq!(desk.reserved, ONE);
        desk.finish_release(0).unwrap();
        assert_eq!(desk.jobs[&0].state, JobState::Released);
        assert_eq!(desk.reserved, 0);
        assert_eq!(desk.available, 9 * ONE);
    }

    #[test]
    fn release_twice() {
        let mut desk = setup();
        desk.hire(AGENT, POSTER, ONE, "1").unwrap();
        desk.begin_release(AGENT, 0, DEPOSIT, None).unwrap();
        desk.finish_release(0).unwrap();
        assert_eq!(desk.begin_release(AGENT, 0, DEPOSIT, None), Err("job not open"));
    }

    #[test]
    fn abort_release_reopens_without_moving_near() {
        let mut desk = setup();
        desk.hire(AGENT, POSTER, ONE, "1").unwrap();
        desk.begin_release(AGENT, 0, DEPOSIT, None).unwrap();
        desk.abort_release(OWNER, 0).unwrap();
        assert_eq!(desk.jobs[&0].state, JobState::Open);
        assert_eq!(desk.reserved, ONE);
        assert_eq!(desk.available, 9 * ONE);
    }

    #[test]
    fn withdraw_cannot_take_reserved() {
        let mut desk = setup();
        desk.hire(AGENT, POSTER, ONE, "1").unwrap();
        assert_eq!(desk.withdraw(OWNER, 10 * ONE), Err("amount exceeds available"));
    }

    #[test]
    fn owner_withdraws_unreserved() {
        let mut desk = setup();
        desk.hire(AGENT, POSTER, ONE, "1").unwrap();
        desk.withdraw(OWNER, 9 * ONE).unwrap();
        assert_eq!(desk.available, 0);
        assert_eq!(desk.reserved, ONE);
    }
}
