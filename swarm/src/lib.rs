use std::collections::BTreeMap;

use hire_logic::swarm::{AgentState as LogicState, Swarm, NEAR_AI_GATEWAY_KEY};
use near_sdk::json_types::U128;
use near_sdk::{env, near, AccountId, NearToken, PanicOnDefault, Promise};

#[near(serializers = [json, borsh])]
#[derive(Clone, PartialEq, Debug)]
pub enum AgentState {
    Pending,
    Approved,
    Closed,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct Agent {
    pub id: u64,
    pub account: AccountId,
    pub deposit: U128,
    pub remaining: U128,
    pub spent: U128,
    pub prompt_hash: String,
    pub kb_hash: String,
    pub tools_hash: String,
    pub state: AgentState,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct Run {
    pub id: u64,
    pub agent_id: u64,
    pub campaign_id: String,
    pub brief_hash: String,
    pub request_hash: String,
    pub response_hash: String,
    pub spend: U128,
}

/// A deposit plus the hashes of a prompt, a knowledge base, and a tool list.
/// The reviewer signature makes the agent eligible. A recorded run must carry
/// a NEAR AI signature over that exact request and response.
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    owner: AccountId,
    reviewer: String,
    owed: u128,
    agents: BTreeMap<u64, Agent>,
    runs: BTreeMap<u64, Run>,
    next_agent: u64,
    next_run: u64,
}

#[near]
impl Contract {
    #[init]
    pub fn new(owner: AccountId, reviewer: String) -> Self {
        if Swarm::new(owner.as_str(), &reviewer, NEAR_AI_GATEWAY_KEY).is_err() {
            env::panic_str("bad reviewer key");
        }
        Self {
            owner,
            reviewer,
            owed: 0,
            agents: BTreeMap::new(),
            runs: BTreeMap::new(),
            next_agent: 0,
            next_run: 0,
        }
    }

    #[payable]
    pub fn join(&mut self, prompt_hash: String, kb_hash: String, tools_hash: String) -> u64 {
        let caller = env::predecessor_account_id();
        let mut swarm = self.swarm();
        let id = match swarm.join(caller.as_str(), env::attached_deposit().as_yoctonear(), &prompt_hash, &kb_hash, &tools_hash) {
            Ok(id) => id,
            Err(error) => env::panic_str(error),
        };
        self.save(swarm);
        id
    }

    pub fn approve(&mut self, id: u64, signature: String) {
        let mut swarm = self.swarm();
        apply(swarm.approve(id, &signature));
        self.save(swarm);
    }

    pub fn record(
        &mut self,
        id: u64,
        campaign_id: String,
        request: String,
        response: String,
        signature: String,
    ) -> u64 {
        let caller = env::predecessor_account_id();
        let mut swarm = self.swarm();
        let run = match swarm.record(caller.as_str(), id, &campaign_id, &request, &response, &signature) {
            Ok(run) => run,
            Err(error) => env::panic_str(error),
        };
        self.save(swarm);
        run
    }

    pub fn withdraw(&mut self, id: u64) -> Promise {
        let caller = env::predecessor_account_id();
        let mut swarm = self.swarm();
        let amount = match swarm.withdraw(caller.as_str(), id) {
            Ok(amount) => amount,
            Err(error) => env::panic_str(error),
        };
        self.save(swarm);
        Promise::new(caller).transfer(NearToken::from_yoctonear(amount))
    }

    pub fn collect(&mut self) -> Promise {
        let caller = env::predecessor_account_id();
        let mut swarm = self.swarm();
        let amount = match swarm.collect(caller.as_str()) {
            Ok(amount) => amount,
            Err(error) => env::panic_str(error),
        };
        self.save(swarm);
        Promise::new(self.owner.clone()).transfer(NearToken::from_yoctonear(amount))
    }

    pub fn get_owner(&self) -> AccountId {
        self.owner.clone()
    }

    pub fn get_reviewer(&self) -> String {
        self.reviewer.clone()
    }

    pub fn get_gateway(&self) -> String {
        NEAR_AI_GATEWAY_KEY.to_string()
    }

    pub fn get_owed(&self) -> U128 {
        U128(self.owed)
    }

    pub fn get_agent(&self, id: u64) -> Option<Agent> {
        self.agents.get(&id).cloned()
    }

    pub fn get_run(&self, id: u64) -> Option<Run> {
        self.runs.get(&id).cloned()
    }

    fn swarm(&self) -> Swarm {
        Swarm {
            owner: self.owner.to_string(),
            reviewer: self.reviewer.clone(),
            gateway: NEAR_AI_GATEWAY_KEY.to_string(),
            owed: self.owed,
            agents: self
                .agents
                .iter()
                .map(|(id, agent)| {
                    (
                        *id,
                        hire_logic::swarm::Agent {
                            id: agent.id,
                            account: agent.account.to_string(),
                            deposit: agent.deposit.0,
                            remaining: agent.remaining.0,
                            spent: agent.spent.0,
                            prompt_hash: agent.prompt_hash.clone(),
                            kb_hash: agent.kb_hash.clone(),
                            tools_hash: agent.tools_hash.clone(),
                            state: to_logic(&agent.state),
                        },
                    )
                })
                .collect(),
            runs: self
                .runs
                .iter()
                .map(|(id, run)| {
                    (
                        *id,
                        hire_logic::swarm::Run {
                            id: run.id,
                            agent_id: run.agent_id,
                            campaign_id: run.campaign_id.clone(),
                            brief_hash: run.brief_hash.clone(),
                            request_hash: run.request_hash.clone(),
                            response_hash: run.response_hash.clone(),
                            spend: run.spend.0,
                        },
                    )
                })
                .collect(),
            next_agent: self.next_agent,
            next_run: self.next_run,
        }
    }

    fn save(&mut self, swarm: Swarm) {
        self.owed = swarm.owed;
        self.next_agent = swarm.next_agent;
        self.next_run = swarm.next_run;
        self.agents = swarm
            .agents
            .into_iter()
            .map(|(id, agent)| {
                (
                    id,
                    Agent {
                        id: agent.id,
                        account: agent.account.parse().expect("account"),
                        deposit: U128(agent.deposit),
                        remaining: U128(agent.remaining),
                        spent: U128(agent.spent),
                        prompt_hash: agent.prompt_hash,
                        kb_hash: agent.kb_hash,
                        tools_hash: agent.tools_hash,
                        state: from_logic(&agent.state),
                    },
                )
            })
            .collect();
        self.runs = swarm
            .runs
            .into_iter()
            .map(|(id, run)| {
                (
                    id,
                    Run {
                        id: run.id,
                        agent_id: run.agent_id,
                        campaign_id: run.campaign_id,
                        brief_hash: run.brief_hash,
                        request_hash: run.request_hash,
                        response_hash: run.response_hash,
                        spend: U128(run.spend),
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

fn to_logic(state: &AgentState) -> LogicState {
    match state {
        AgentState::Pending => LogicState::Pending,
        AgentState::Approved => LogicState::Approved,
        AgentState::Closed => LogicState::Closed,
    }
}

fn from_logic(state: &LogicState) -> AgentState {
    match state {
        LogicState::Pending => AgentState::Pending,
        LogicState::Approved => AgentState::Approved,
        LogicState::Closed => AgentState::Closed,
    }
}
