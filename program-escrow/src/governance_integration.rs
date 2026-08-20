//! Governance Integration Module
//!
//! Wires grainlify-core governance state into escrow contracts for upgrade and configuration control.

use soroban_sdk::{contractclient, Address, BytesN, Env, Symbol};

/// Storage key for governance contract address
const GOVERNANCE_CONTRACT: Symbol = soroban_sdk::symbol_short!("GOV_ADDR");

/// Storage key for minimum required governance version
const MIN_GOV_VERSION: Symbol = soroban_sdk::symbol_short!("MIN_VER");

#[contractclient(name = "GovernanceClient")]
#[allow(dead_code)]
pub trait GovernanceInterface {
    fn get_ver(env: Env) -> u32;
    fn is_upg_ok(env: Env, wasm_hash: BytesN<32>) -> bool;
    /// Returns true when a proposal identified by `proposal_id` has been
    /// vetoed or cancelled before execution.  A vetoed proposal must never
    /// be executed even if it previously reached `Approved` status.
    fn is_vetoed(env: Env, proposal_id: u32) -> bool;
    fn execute_proposal(env: Env, proposal_id: u32) -> Result<(), GovernanceError>;
}

#[soroban_sdk::contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum GovernanceError {
    NotInitialized = 1,
    InvalidThreshold = 2,
    ThresholdTooLow = 3,
    InsufficientStake = 4,
    ProposalsNotFound = 5,
    ProposalNotFound = 6,
    ProposalNotActive = 7,
    VotingNotStarted = 8,
    VotingEnded = 9,
    VotingStillActive = 10,
    AlreadyVoted = 11,
    ProposalNotApproved = 12,
    ExecutionDelayNotMet = 13,
    ProposalExpired = 14,
    ZeroVotingPower = 15,
    InvalidTotalVotingPower = 16,
    Unauthorized = 17,
}

/// Set the governance contract address (admin only)
pub fn set_governance_contract(env: &Env, governance_addr: Address) {
    env.storage()
        .instance()
        .set(&GOVERNANCE_CONTRACT, &governance_addr);
}

/// Get the governance contract address
pub fn get_governance_contract(env: &Env) -> Option<Address> {
    env.storage().instance().get(&GOVERNANCE_CONTRACT)
}

/// Set minimum required governance version
pub fn set_min_governance_version(env: &Env, min_version: u32) {
    env.storage().instance().set(&MIN_GOV_VERSION, &min_version);
}

/// Get minimum required governance version
pub fn get_min_governance_version(env: &Env) -> u32 {
    env.storage().instance().get(&MIN_GOV_VERSION).unwrap_or(0)
}

/// Check if governance contract is configured and meets minimum version.
///
/// **Default-Allow Behavior**: If no governance contract address is configured,
/// or if `min_version` is left at its default (0), this function intentionally
/// returns `true`. This allows the escrow to operate permissionlessly before
/// a governance layer is explicitly attached and version-gated.
pub fn check_governance_version(env: &Env) -> bool {
    if let Some(gov_addr) = get_governance_contract(env) {
        let min_version = get_min_governance_version(env);
        if min_version > 0 {
            let version = GovernanceClient::new(env, &gov_addr).get_ver();
            return version >= min_version;
        }
    }
    true // No governance configured or no minimum version set
}

/// Check if an upgrade hash is approved by an executed governance proposal.
pub fn check_upgrade_approval(env: &Env, wasm_hash: &BytesN<32>) -> bool {
    let Some(gov_addr) = get_governance_contract(env) else {
        return false;
    };

    if !check_governance_version(env) {
        return false;
    }

    GovernanceClient::new(env, &gov_addr).is_upg_ok(wasm_hash)
}

/// Check whether a governance proposal has been vetoed or cancelled.
///
/// Returns `true` when the governance contract reports the proposal as
/// vetoed/cancelled, meaning it **must not** be executed even if it
/// previously reached `Approved` status.  Returns `false` when no
/// governance contract is configured (open/permissionless mode).
pub fn check_proposal_vetoed(env: &Env, proposal_id: u32) -> bool {
    let Some(gov_addr) = get_governance_contract(env) else {
        return false;
    };

    GovernanceClient::new(env, &gov_addr).is_vetoed(&proposal_id)
}

/// Validate and consume an approved, non-vetoed governance proposal before a
/// governance-triggered escrow action proceeds.
///
/// This is the real code path `check_proposal_vetoed` was declared for: it
/// delegates to grainlify-core's `execute_proposal` (so quorum, approval
/// threshold, execution delay, and replay protection are enforced by the
/// governance module itself, not a caller-supplied flag), and additionally
/// rejects a proposal `check_proposal_vetoed` reports as vetoed/cancelled —
/// closing the gap where the veto check existed but nothing ever called it.
pub fn execute_governance_proposal(env: &Env, proposal_id: u32) -> bool {
    let Some(gov_addr) = get_governance_contract(env) else {
        return false;
    };

    if !check_governance_version(env) {
        return false;
    }

    if check_proposal_vetoed(env, proposal_id) {
        return false;
    }

    matches!(
        GovernanceClient::new(env, &gov_addr).try_execute_proposal(&proposal_id),
        Ok(Ok(()))
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    #[soroban_sdk::contract]
    struct MockGov;

    #[soroban_sdk::contractimpl]
    impl MockGov {
        pub fn get_ver(_env: Env) -> u32 {
            2
        }
    }

    #[test]
    fn test_check_governance_version_default_allow_unconfigured() {
        let env = Env::default();
        let contract_id = env.register_contract(None, MockGov);
        // Never-configured contract should default-allow
        env.as_contract(&contract_id, || {
            assert!(check_governance_version(&env));
        });
    }

    #[test]
    fn test_check_governance_version_default_allow_zero_min_version() {
        let env = Env::default();
        let contract_id = env.register_contract(None, MockGov);
        let dummy_gov = Address::generate(&env);

        env.as_contract(&contract_id, || {
            set_governance_contract(&env, dummy_gov);
            // Configured but min_version is 0 (default) - should default-allow
            // without attempting a cross-contract call. We know no call is attempted
            // because `dummy_gov` is not a registered contract, so calling it would panic.
            assert!(check_governance_version(&env));
        });
    }

    #[test]
    fn test_check_governance_version_gated_transition() {
        let env = Env::default();
        let contract_id = env.register_contract(None, MockGov);
        let gov_id = env.register_contract(None, MockGov); // A separate contract as the governance contract

        env.as_contract(&contract_id, || {
            // Start unconfigured
            assert!(check_governance_version(&env));

            // Transition to configured with min_version 0
            set_governance_contract(&env, gov_id.clone());
            assert!(check_governance_version(&env));

            // Transition to actually gated (min_version > 0)
            set_min_governance_version(&env, 1);
            // Mock returns 2, which is >= 1
            assert!(check_governance_version(&env));

            // Test failing gate
            set_min_governance_version(&env, 3);
            // Mock returns 2, which is < 3
            assert!(!check_governance_version(&env));
        });
    }
}
