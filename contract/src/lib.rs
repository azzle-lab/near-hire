use std::collections::BTreeMap;

use hire_logic::{Desk, JobState as LogicState};
use near_sdk::json_types::U128;
use near_sdk::{env, near, AccountId, Gas, NearToken, PanicOnDefault, Promise};

const BUFFER: u128 = 30_000_000_000_000_000_000_000;
const STORAGE_DEPOSIT: u128 = 2_000_000_000_000_000_000_000;

#[near(serializers = [json, borsh])]
#[derive(Clone, PartialEq, Debug)]
pub enum JobState {
    Open,
    Releasing,
    Released,
    Cancelled,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct Job {
    pub id: u64,
    pub hirer: AccountId,
    pub amount: U128,
    pub base_recipient: String,
    pub amount_out: String,
    pub state: JobState,
    pub deposit_account: Option<String>,
    pub memo: Option<String>,
}

/// Owner-funded treasury. An agent may reserve NEAR for a Base USDC payout.
/// The reservation names the AZZLE poster. It does not choose who receives the NEAR.
/// Rules live in `hire-logic`. This file is the NEAR wrapper.
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    owner: AccountId,
    wrap: AccountId,
    buffer: u128,
    available: u128,
    reserved: u128,
    caps: BTreeMap<AccountId, u128>,
    jobs: BTreeMap<u64, Job>,
    next_id: u64,
}

#[near]
impl Contract {
    #[init]
    pub fn new(owner: AccountId, wrap: AccountId) -> Self {
        Self {
            owner,
            wrap,
            buffer: 0,
            available: 0,
            reserved: 0,
            caps: BTreeMap::new(),
            jobs: BTreeMap::new(),
            next_id: 0,
        }
    }

    /// First 0.03 NEAR stays as a wrap buffer. The rest is the hire treasury.
    #[payable]
    pub fn fund(&mut self) {
        let caller = env::predecessor_account_id();
        if caller != self.owner {
            env::panic_str("owner only");
        }
        let mut amount = env::attached_deposit().as_yoctonear();
        if amount == 0 {
            env::panic_str("deposit required");
        }
        if self.buffer < BUFFER {
            let skim = amount.min(BUFFER - self.buffer);
            self.buffer += skim;
            amount -= skim;
        }
        if amount == 0 {
            return;
        }
        let mut desk = self.desk();
        apply(desk.fund(caller.as_str(), amount));
        self.save(desk);
    }

    pub fn set_cap(&mut self, agent: AccountId, cap: U128) {
        let caller = env::predecessor_account_id();
        let mut desk = self.desk();
        apply(desk.set_cap(caller.as_str(), agent.as_str(), cap.0));
        self.save(desk);
    }

    /// Reserve `amount` yoctoNEAR against the caller's cap. Takes no deposit:
    /// a function-call key cannot attach NEAR.
    pub fn hire(&mut self, base_recipient: String, amount: U128, amount_out: String) -> u64 {
        let caller = env::predecessor_account_id();
        let mut desk = self.desk();
        let id = match desk.hire(caller.as_str(), &base_recipient, amount.0, &amount_out) {
            Ok(id) => id,
            Err(error) => env::panic_str(error),
        };
        self.save(desk);
        id
    }

    pub fn cancel(&mut self, id: u64) {
        let caller = env::predecessor_account_id();
        let mut desk = self.desk();
        apply(desk.cancel(caller.as_str(), id));
        self.save(desk);
    }

    /// Hirer sends wNEAR to the deposit address in a 1Click-signed quote for this job.
    /// The quote's recipient, amount, and Base USDC asset must match the hire.
    pub fn release(&mut self, id: u64, payload: String, signature: String) -> Promise {
        let caller = env::predecessor_account_id();
        let mut desk = self.desk();
        let job = match desk.jobs.get(&id).cloned() {
            Some(job) => job,
            None => env::panic_str("unknown job"),
        };
        let bound = match hire_logic::bind_quote(&payload, &signature, &job) {
            Ok(bound) => bound,
            Err(error) => env::panic_str(error),
        };
        let amount = match desk.begin_release(caller.as_str(), id, &bound.deposit_account, bound.memo.as_deref()) {
            Ok(amount) => amount,
            Err(error) => env::panic_str(error),
        };
        let deposit = match bound.deposit_account.parse() {
            Ok(account) => account,
            Err(_) => env::panic_str("bad deposit account"),
        };
        let memo = bound.memo;
        self.save(desk);
        self.send_wnear(id, deposit, amount, true, memo)
    }

    /// Hirer retries the wNEAR transfer to the deposit account already stored on the job.
    pub fn retry_send(&mut self, id: u64) -> Promise {
        let caller = env::predecessor_account_id();
        let job = match self.jobs.get(&id).cloned() {
            Some(job) => job,
            None => env::panic_str("unknown job"),
        };
        if caller != job.hirer && caller != self.owner {
            env::panic_str("only hirer or owner");
        }
        if job.state != JobState::Releasing {
            env::panic_str("job not releasing");
        }
        let deposit = match job.deposit_account.clone() {
            Some(account) => account,
            None => env::panic_str("deposit missing"),
        };
        let account = match deposit.parse() {
            Ok(account) => account,
            Err(_) => env::panic_str("bad deposit account"),
        };
        self.send_wnear(id, account, job.amount.0, false, job.memo)
    }

    /// Owner reopens a releasing job after wNEAR was refunded as native NEAR.
    pub fn abort(&mut self, id: u64) {
        let caller = env::predecessor_account_id();
        let mut desk = self.desk();
        apply(desk.abort_release(caller.as_str(), id));
        self.save(desk);
    }

    #[private]
    pub fn on_release_result(&mut self, id: u64) {
        if env::promise_result_checked(0, 1024).is_err() {
            env::panic_str("wNEAR transfer failed; job stays releasing");
        }
        let mut desk = self.desk();
        apply(desk.finish_release(id));
        self.save(desk);
    }

    /// Owner withdraws unreserved NEAR. Open hires stay locked.
    pub fn withdraw(&mut self, amount: U128) -> Promise {
        let caller = env::predecessor_account_id();
        let mut desk = self.desk();
        apply(desk.withdraw(caller.as_str(), amount.0));
        self.save(desk);
        Promise::new(self.owner.clone()).transfer(NearToken::from_yoctonear(amount.0))
    }

    pub fn get_owner(&self) -> AccountId {
        self.owner.clone()
    }

    pub fn get_wrap(&self) -> AccountId {
        self.wrap.clone()
    }

    pub fn get_buffer(&self) -> U128 {
        U128(self.buffer)
    }

    pub fn get_available(&self) -> U128 {
        U128(self.available)
    }

    pub fn get_reserved(&self) -> U128 {
        U128(self.reserved)
    }

    pub fn get_cap(&self, agent: AccountId) -> U128 {
        U128(self.caps.get(&agent).copied().unwrap_or(0))
    }

    pub fn get_job(&self, id: u64) -> Option<Job> {
        self.jobs.get(&id).cloned()
    }

    fn desk(&self) -> Desk {
        Desk {
            owner: self.owner.to_string(),
            available: self.available,
            reserved: self.reserved,
            caps: self.caps.iter().map(|(agent, cap)| (agent.to_string(), *cap)).collect(),
            jobs: self
                .jobs
                .iter()
                .map(|(id, job)| {
                    (
                        *id,
                        hire_logic::Job {
                            id: job.id,
                            hirer: job.hirer.to_string(),
                            amount: job.amount.0,
                            base_recipient: job.base_recipient.clone(),
                            amount_out: job.amount_out.clone(),
                            state: to_logic(&job.state),
                            deposit_account: job.deposit_account.clone(),
                            memo: job.memo.clone(),
                        },
                    )
                })
                .collect(),
            next_id: self.next_id,
        }
    }

    fn save(&mut self, desk: Desk) {
        self.available = desk.available;
        self.reserved = desk.reserved;
        self.next_id = desk.next_id;
        self.caps = desk
            .caps
            .into_iter()
            .map(|(agent, cap)| (agent.parse().expect("account"), cap))
            .collect();
        self.jobs = desk
            .jobs
            .into_iter()
            .map(|(id, job)| {
                (
                    id,
                    Job {
                        id: job.id,
                        hirer: job.hirer.parse().expect("account"),
                        amount: U128(job.amount),
                        base_recipient: job.base_recipient,
                        amount_out: job.amount_out,
                        state: from_logic(&job.state),
                        deposit_account: job.deposit_account,
                        memo: job.memo,
                    },
                )
            })
            .collect();
    }
}

fn apply(result: Result<(), &'static str>) {
    if let Err(error) = result {
        env::panic_str(error);
    }
}

fn to_logic(state: &JobState) -> LogicState {
    match state {
        JobState::Open => LogicState::Open,
        JobState::Releasing => LogicState::Releasing,
        JobState::Released => LogicState::Released,
        JobState::Cancelled => LogicState::Cancelled,
    }
}

fn from_logic(state: &LogicState) -> JobState {
    match state {
        LogicState::Open => JobState::Open,
        LogicState::Releasing => JobState::Releasing,
        LogicState::Released => JobState::Released,
        LogicState::Cancelled => JobState::Cancelled,
    }
}

impl Contract {
    fn send_wnear(
        &mut self,
        id: u64,
        deposit_account: AccountId,
        amount: u128,
        wrap_first: bool,
        memo: Option<String>,
    ) -> Promise {
        let yocto = if wrap_first { STORAGE_DEPOSIT + 1 } else { 1 };
        if self.buffer < yocto {
            env::panic_str("fund the wrap buffer");
        }
        self.buffer -= yocto;
        let wrap = self.wrap.clone();
        let transfer_args = near_sdk::serde_json::json!({
            "receiver_id": deposit_account,
            "amount": amount.to_string(),
            "memo": memo,
        })
        .to_string()
        .into_bytes();
        let callback_args = near_sdk::serde_json::json!({ "id": id }).to_string().into_bytes();
        let transfer = Promise::new(wrap.clone()).function_call(
            "ft_transfer",
            transfer_args,
            NearToken::from_yoctonear(1),
            Gas::from_tgas(30),
        );
        let callback = Promise::new(env::current_account_id()).function_call(
            "on_release_result",
            callback_args,
            NearToken::from_yoctonear(0),
            Gas::from_tgas(15),
        );
        if !wrap_first {
            return transfer.then(callback);
        }
        let storage_args = near_sdk::serde_json::json!({
            "account_id": env::current_account_id(),
        })
        .to_string()
        .into_bytes();
        Promise::new(wrap)
            .function_call(
                "storage_deposit",
                storage_args,
                NearToken::from_yoctonear(STORAGE_DEPOSIT),
                Gas::from_tgas(20),
            )
            .function_call(
                "near_deposit",
                vec![],
                NearToken::from_yoctonear(amount),
                Gas::from_tgas(20),
            )
            .then(transfer)
            .then(callback)
    }
}
