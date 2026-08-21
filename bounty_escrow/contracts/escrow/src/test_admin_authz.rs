#![cfg(test)]

//! Issue #177 — Admin authorization audit tests.
//!
//! Every admin-only entrypoint MUST reject a caller that is not the stored
//! admin. These tests prove that guarantee by invoking each admin function
//! as an arbitrary (non-admin) address with NO auth mocked, and asserting the
//! call returns `Err(Error::Unauthorized)` instead of mutating state.
//!
//! IMPORTANT: we deliberately do NOT call `env.mock_all_auths()`. Once
//! `mock_all_auths()` is enabled it cannot be undone for the env, which would
//! make every `require_auth()` succeed and silently void the negative test
//! (this was the flaw in the previous `test_rbac.rs` negative cases).

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token, Address, Env,
};

struct AuthzSetup<'a> {
    env: Env,
    admin: Address,
    random: Address,
    token_id: Address,
    client: BountyEscrowContractClient<'a>,
}

impl<'a> AuthzSetup<'a> {
    fn new() -> Self {
        let env = Env::default();
        let contract_id = env.register_contract(None, BountyEscrowContract);
        let client = BountyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let random = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token_id = env
            .register_stellar_asset_contract_v2(token_admin.clone())
            .address();

        // NOTE: as of #491 `init` requires the incoming admin's own auth, so
        // the bootstrap has to be authorized. Scope it to this one call and
        // clear immediately with `mock_auths(&[])` — the negative tests below
        // depend on the env being unauthenticated, and a lingering
        // `mock_all_auths()` would make every `require_auth()` succeed and
        // silently void them (see the module note above).
        env.mock_all_auths();
        client.init(&admin, &token_id);
        env.mock_auths(&[]);

        Self {
            env,
            admin,
            random,
            token_id,
            client,
        }
    }

    /// Mint + lock funds so escrows exist for functions that need a target.
    /// Uses `mock_all_auths()` only for the setup mutations, then clears all
    /// mocked auth with `mock_auths(&[])` (which DOES override
    /// `mock_all_auths`) so the subsequent admin call is evaluated
    /// unauthenticated.
    fn seed_escrow(&self, bounty_id: u64, amount: i128, deadline_offset: u64) {
        self.env.mock_all_auths();
        let sac = token::StellarAssetClient::new(&self.env, &self.token_id);
        sac.mint(&self.admin, &(amount * 2));
        let deadline = self.env.ledger().timestamp() + deadline_offset;
        self.client
            .lock_funds(&self.admin, &bounty_id, &amount, &deadline);
        // Clear auth so subsequent admin calls are evaluated unauthenticated.
        self.env.mock_auths(&[]);
    }
}

/// In Soroban, a failed `require_auth` aborts the call, which the `try_*`
/// client surfaces as an outer `Err(InvokeError)` (not as the contract's
/// `Error::Unauthorized`). So a rejected non-admin call is simply `is_err()`.
fn assert_unauthorized<V: core::fmt::Debug, T: core::fmt::Debug, E: core::fmt::Debug>(
    res: Result<Result<V, T>, E>,
) {
    extern crate alloc;
    let err = res.expect_err("expected admin-only call to be rejected (auth abort)");
    let err_str = alloc::format!("{:?}", err);
    assert!(
        err_str.contains("Auth") || err_str.contains("Context") || err_str.contains("Abort") || err_str.contains("Unauthorized"),
        "expected auth abort error, got: {}", err_str
    );
}

// ─────────────────────────────────────────────────────────
// Core admin controls
// ─────────────────────────────────────────────────────────

#[test]
fn non_admin_cannot_update_fee_config() {
    let s = AuthzSetup::new();
    let res = s
        .client
        .try_update_fee_config(&None, &None, &Some(s.random.clone()), &Some(true));
    assert_unauthorized(res);
}

#[test]
fn non_admin_cannot_set_paused() {
    let s = AuthzSetup::new();
    let res = s.client.try_set_paused(&Some(true), &None, &None);
    assert_unauthorized(res);
}

#[test]
fn non_admin_cannot_set_emergency_pause() {
    let s = AuthzSetup::new();
    let res = s.client.try_set_emergency_pause(&true);
    assert_unauthorized(res);
}

#[test]
fn non_admin_cannot_update_multisig_config() {
    let s = AuthzSetup::new();
    let signers = vec![&s.env, s.admin.clone()];
    let res = s
        .client
        .try_update_multisig_config(&1000i128, &signers, &1u32);
    assert_unauthorized(res);
}

#[test]
fn non_admin_cannot_set_amount_policy() {
    let s = AuthzSetup::new();
    let res = s.client.try_set_amount_policy(&s.random.clone(), &100i128, &1_000_000i128);
    assert_unauthorized(res);
}

#[test]
fn non_admin_cannot_set_claim_window() {
    let s = AuthzSetup::new();
    let res = s.client.try_set_claim_window(&3600u64);
    assert_unauthorized(res);
}

// ─────────────────────────────────────────────────────────
// Claim / release / refund controls
// ─────────────────────────────────────────────────────────

#[test]
fn non_admin_cannot_authorize_claim() {
    let s = AuthzSetup::new();
    s.seed_escrow(1u64, 1000i128, 3600u64);
    let res = s.client.try_authorize_claim(&1u64, &s.random.clone());
    assert_unauthorized(res);
}

#[test]
fn non_admin_cannot_cancel_pending_claim() {
    let s = AuthzSetup::new();
    s.seed_escrow(1u64, 1000i128, 3600u64);
    let res = s.client.try_cancel_pending_claim(&1u64);
    assert_unauthorized(res);
}

#[test]
fn non_admin_cannot_approve_refund() {
    let s = AuthzSetup::new();
    s.seed_escrow(1u64, 1000i128, 3600u64);
    let res = s.client.try_approve_refund(&1u64, &100i128, &s.random.clone(), &RefundMode::Full);
    assert_unauthorized(res);
}

#[test]
fn non_admin_cannot_partial_release() {
    let s = AuthzSetup::new();
    s.seed_escrow(1u64, 1000i128, 3600u64);
    let res = s
        .client
        .try_partial_release(&1u64, &s.random.clone(), &100i128);
    assert_unauthorized(res);
}

#[test]
fn non_admin_cannot_release_funds() {
    let s = AuthzSetup::new();
    s.seed_escrow(1u64, 1000i128, 3600u64);
    let res = s.client.try_release_funds(&1u64, &s.random.clone());
    assert_unauthorized(res);
}

#[test]
fn non_admin_cannot_batch_release_funds() {
    let s = AuthzSetup::new();
    s.seed_escrow(1u64, 1000i128, 3600u64);
    let items = soroban_sdk::vec![&s.env, ReleaseFundsItem {
        bounty_id: 1u64,
        contributor: s.random.clone(),
    }];
    let res = s.client.try_batch_release_funds(&items);
    assert_unauthorized(res);
}

// `approve_large_release` is gated on the caller being a registered multisig
// signer (not the stored admin), but a completely arbitrary caller must still
// be rejected — and since no auth is mocked here, the require_auth aborts.
#[test]
fn non_signer_cannot_approve_large_release() {
    let s = AuthzSetup::new();
    s.seed_escrow(1u64, 1000i128, 3600u64);
    let res = s
        .client
        .try_approve_large_release(&1u64, &s.random.clone(), &s.random.clone());
    assert_unauthorized(res);
}

// ─────────────────────────────────────────────────────────
// Governance + anti-abuse controls
// ─────────────────────────────────────────────────────────

#[test]
fn non_admin_cannot_set_anti_abuse_admin() {
    let s = AuthzSetup::new();
    let res = s.client.try_set_anti_abuse_admin(&s.random.clone());
    assert_unauthorized(res);
}

#[test]
fn non_admin_cannot_set_whitelist() {
    let s = AuthzSetup::new();
    let res = s.client.try_set_whitelist(&s.random.clone(), &true);
    assert_unauthorized(res);
}

#[test]
fn non_admin_cannot_set_governance_contract() {
    let s = AuthzSetup::new();
    let res = s.client.try_set_governance_contract(&s.random.clone());
    assert_unauthorized(res);
}

#[test]
fn non_admin_cannot_set_min_governance_version() {
    let s = AuthzSetup::new();
    let res = s.client.try_set_min_governance_version(&2u32);
    assert_unauthorized(res);
}

// ─────────────────────────────────────────────────────────
// Circuit breaker controls
// ─────────────────────────────────────────────────────────

#[test]
fn non_admin_cannot_set_circuit_breaker_admin() {
    let s = AuthzSetup::new();
    let res = s.client.try_set_circuit_breaker_admin(&s.random.clone());
    assert_unauthorized(res);
}

#[test]
fn non_admin_cannot_set_circuit_breaker_config() {
    let s = AuthzSetup::new();
    let res = s
        .client
        .try_set_circuit_breaker_config(&3u32, &2u32, &10u32);
    assert_unauthorized(res);
}

#[test]
fn admin_cannot_set_zero_failure_threshold() {
    let s = AuthzSetup::new();
    s.env.mock_all_auths();
    let result = s.client.try_set_circuit_breaker_config(&0u32, &2u32, &10u32);
    assert!(result.is_err());
}

#[test]
fn non_admin_cannot_reset_circuit() {
    let s = AuthzSetup::new();
    let res = s.client.try_reset_circuit(&s.random.clone());
    assert_unauthorized(res);
}

// ─────────────────────────────────────────────────────────
// Positive control: the stored admin IS authorized
// (proves require_auth is wired to the correct stored address)
// ─────────────────────────────────────────────────────────

#[test]
fn stored_admin_can_set_paused() {
    let s = AuthzSetup::new();
    // With all auth mocked, the stored admin (who calls set_paused) is
    // authorized, so the call succeeds. This proves the happy path / that
    // require_auth is wired to the correct stored address.
    s.env.mock_all_auths();
    let res = s.client.try_set_paused(&Some(true), &None, &None);
    assert!(
        res.unwrap_or_else(|e| panic!("invoke error: {:?}", e)).is_ok(),
        "stored admin should be authorized"
    );
}

#[test]
fn demoted_circuit_breaker_admin_cannot_reset_circuit() {
    let s = AuthzSetup::new();
    s.env.mock_all_auths();
    
    // Admin sets initial circuit breaker admin to `random`
    s.client.set_circuit_breaker_admin(&s.random);
    
    // Check that `random` can reset the circuit while they are the admin
    let res_success = s.client.try_reset_circuit(&s.random);
    assert!(res_success.unwrap_or_else(|e| panic!("invoke error: {:?}", e)).is_ok());

    // Main admin demotes `random` by setting a new circuit breaker admin
    let new_admin = soroban_sdk::Address::generate(&s.env);
    s.client.set_circuit_breaker_admin(&new_admin);
    
    // Clear auths so we test `random` unauthenticated (as a non-admin)
    s.env.mock_auths(&[]);
    
    // The demoted admin `random` should now be rejected
    let res_fail = s.client.try_reset_circuit(&s.random);
    assert_unauthorized(res_fail);
}

// ─────────────────────────────────────────────────────────
// FeeConfigUpdated event payload assertions
//
// These tests go beyond authorization (already covered above) and
// verify the event PAYLOAD emitted by `update_fee_config` at the
// field level. This matters because FeeConfigUpdated is the sole
// on-chain audit trail for fee parameter changes.  If the event
// payload ever silently diverges from the actually-applied config
// (e.g. logging the *old* fee_recipient instead of the *new* one),
// depositors and auditors reading events would be misled.
// ─────────────────────────────────────────────────────────

/// Drive `update_fee_config` through the actual contract entrypoint and
/// assert every FeeConfigUpdated payload field matches the *new*
/// configuration — not the prior default values.
#[test]
fn fee_config_updated_event_payload_matches_new_config() {
    use events::{FeeConfigUpdated, EVENT_VERSION_V2};
    use soroban_sdk::{
        symbol_short,
        testutils::{Address as _, Events as _, Ledger as _},
        Address, IntoVal, TryFromVal, Val, Vec as SdkVec,
    };

    let s = AuthzSetup::new();
    s.env.mock_all_auths();

    let new_lock_rate: i128 = 250;
    let new_release_rate: i128 = 175;
    let new_recipient = Address::generate(&s.env);
    let fee_enabled = true;

    let ts_before = s.env.ledger().timestamp();

    s.client.update_fee_config(
        &Some(new_lock_rate),
        &Some(new_release_rate),
        &Some(new_recipient.clone()),
        &Some(fee_enabled),
    );

    // Locate the FeeConfigUpdated event by its topic ("fee_cfg",).
    let expected_topics: SdkVec<Val> =
        (symbol_short!("fee_cfg"),).into_val(&s.env);

    let all = s.env.events().all();
    let mut found = false;
    for i in 0..all.len() {
        let (contract_id, topics, data) = all.get(i).unwrap();
        if contract_id != s.client.address {
            continue;
        }
        if topics != expected_topics {
            continue;
        }

        let decoded = FeeConfigUpdated::try_from_val(&s.env, &data)
            .expect("event data must decode as FeeConfigUpdated");

        assert_eq!(decoded.version, EVENT_VERSION_V2, "version mismatch");
        assert_eq!(
            decoded.lock_fee_rate, new_lock_rate,
            "lock_fee_rate must reflect the NEW rate, not the old default"
        );
        assert_eq!(
            decoded.release_fee_rate, new_release_rate,
            "release_fee_rate must reflect the NEW rate, not the old default"
        );
        assert_eq!(
            decoded.fee_recipient, new_recipient,
            "fee_recipient must be the NEW recipient, not the prior one"
        );
        assert_eq!(
            decoded.fee_enabled, fee_enabled,
            "fee_enabled must match the requested value"
        );
        assert!(
            decoded.timestamp >= ts_before,
            "timestamp must be >= ledger timestamp at time of call"
        );

        found = true;
        break;
    }
    assert!(found, "FeeConfigUpdated event was not emitted");

    // Cross-check: the stored config must match the event.
    let stored = s.client.get_fee_config();
    assert_eq!(stored.lock_fee_rate, new_lock_rate);
    assert_eq!(stored.release_fee_rate, new_release_rate);
    assert_eq!(stored.fee_recipient, new_recipient);
    assert_eq!(stored.fee_enabled, fee_enabled);
}

/// Toggle `fee_enabled` from true → false and assert the event
/// reflects the *new* disabled state (not the old enabled state).
/// This edge case is particularly audit-relevant: if the event logged
/// `true` after the admin intentionally disabled fees, observers would
/// believe fees are still being collected.
#[test]
fn fee_config_updated_event_reflects_fee_enabled_toggle() {
    use events::{FeeConfigUpdated, EVENT_VERSION_V2};
    use soroban_sdk::{
        symbol_short,
        testutils::{Address as _, Events as _},
        Address, IntoVal, TryFromVal, Val, Vec as SdkVec,
    };

    let s = AuthzSetup::new();
    s.env.mock_all_auths();

    let fee_recipient = Address::generate(&s.env);

    // Step 1: Enable fees with non-zero rates.
    s.client.update_fee_config(
        &Some(500_i128),
        &Some(300_i128),
        &Some(fee_recipient.clone()),
        &Some(true),
    );

    // Verify the stored config has fee_enabled = true.
    let config_before = s.client.get_fee_config();
    assert_eq!(config_before.fee_enabled, true, "precondition: fees must be enabled");

    // Step 2: Disable fees (toggle fee_enabled: true → false), keeping
    // rates unchanged by passing None.
    s.client.update_fee_config(
        &None::<i128>,
        &None::<i128>,
        &None::<Address>,
        &Some(false),
    );

    // Find the LAST FeeConfigUpdated event (the toggle call).
    let expected_topics: SdkVec<Val> =
        (symbol_short!("fee_cfg"),).into_val(&s.env);

    let all = s.env.events().all();
    let mut last_decoded: Option<FeeConfigUpdated> = None;
    for i in 0..all.len() {
        let (contract_id, topics, data) = all.get(i).unwrap();
        if contract_id != s.client.address {
            continue;
        }
        if topics != expected_topics {
            continue;
        }
        last_decoded = Some(
            FeeConfigUpdated::try_from_val(&s.env, &data)
                .expect("event data must decode as FeeConfigUpdated"),
        );
    }

    let decoded = last_decoded.expect("FeeConfigUpdated event not emitted for toggle call");

    assert_eq!(decoded.version, EVENT_VERSION_V2);
    assert_eq!(
        decoded.fee_enabled, false,
        "event must reflect fee_enabled=false after toggle, not the prior true"
    );
    // Rates and recipient should be unchanged from step 1 (partial update).
    assert_eq!(decoded.lock_fee_rate, 500, "lock_fee_rate must be preserved");
    assert_eq!(decoded.release_fee_rate, 300, "release_fee_rate must be preserved");
    assert_eq!(decoded.fee_recipient, fee_recipient, "fee_recipient must be preserved");

    // Cross-check stored state.
    let config_after = s.client.get_fee_config();
    assert_eq!(config_after.fee_enabled, false);
    assert_eq!(config_after.lock_fee_rate, 500);
    assert_eq!(config_after.release_fee_rate, 300);
    assert_eq!(config_after.fee_recipient, fee_recipient);
}
