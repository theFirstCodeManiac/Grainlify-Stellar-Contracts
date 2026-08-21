#![cfg(test)]

//! Issue #316 — `approve_large_release` authorization + duplicate-approver coverage.
//!
//! `approve_large_release` is the multisig gate for large-value releases: only an
//! address present in the stored `MultisigConfig.signers` may record an approval,
//! and a signer approving twice must be a no-op (not a double-count). Neither gap
//! was covered before this file: `test_admin_authz::non_signer_cannot_approve_large_release`
//! only exercises the *default, never-configured* signer set, and no test exercised
//! a configured-but-excluded signer, nor the duplicate-approval no-op path.

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Events},
    vec, Address, Env,
};

fn create_token_contract<'a>(
    e: &Env,
    admin: &Address,
) -> (token::Client<'a>, token::StellarAssetClient<'a>) {
    let contract_address = e.register_stellar_asset_contract(admin.clone());
    (
        token::Client::new(e, &contract_address),
        token::StellarAssetClient::new(e, &contract_address),
    )
}

fn create_escrow_contract<'a>(e: &Env) -> BountyEscrowContractClient<'a> {
    let contract_id = e.register_contract(None, BountyEscrowContract);
    BountyEscrowContractClient::new(e, &contract_id)
}

struct TestSetup<'a> {
    env: Env,
    admin: Address,
    depositor: Address,
    contributor: Address,
    escrow: BountyEscrowContractClient<'a>,
}

impl<'a> TestSetup<'a> {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);
        let contributor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        let escrow = create_escrow_contract(&env);

        escrow.init(&admin, &token.address);
        token_admin.mint(&depositor, &10_000_000);

        Self {
            env,
            admin,
            depositor,
            contributor,
            escrow,
        }
    }

    /// Lock a bounty large enough to be a plausible "large release" candidate.
    fn lock(&self, bounty_id: u64, amount: i128) {
        let deadline = self.env.ledger().timestamp() + 10_000;
        self.escrow
            .lock_funds(&self.depositor, &bounty_id, &amount, &deadline);
    }

    /// Read the persisted `ReleaseApproval` for a bounty directly out of contract
    /// storage. There is no public getter for this record, so we reach into
    /// storage the same way `test_expiration_and_dispute.rs` / `test_reentrancy.rs`
    /// do via `env.as_contract`.
    fn read_release_approval(&self, bounty_id: u64) -> Option<ReleaseApproval> {
        self.env.as_contract(&self.escrow.address, || {
            self.env
                .storage()
                .persistent()
                .get(&DataKey::ReleaseApproval(bounty_id))
        })
    }
}

// ─────────────────────────────────────────────────────────
// 1. Non-signer with a configured multisig must be rejected.
// ─────────────────────────────────────────────────────────

#[test]
fn non_signer_with_configured_multisig_is_rejected() {
    let s = TestSetup::new();
    s.lock(1_000, 50_000);

    // Configure the multisig with `admin` as the sole signer.
    s.escrow
        .update_multisig_config(&1_i128, &vec![&s.env, s.admin.clone()], &1);

    // A brand-new address that was never added to `signers` attempts to approve.
    // `mock_all_auths()` is active (so `require_auth` would trivially succeed for
    // anyone) — this proves rejection comes from the `is_signer` membership check
    // itself, not from an auth failure, i.e. this is genuinely "wrong signer",
    // not an accidental auth-mocking artifact.
    let outsider = Address::generate(&s.env);
    let result = s
        .escrow
        .try_approve_large_release(&1_000, &s.contributor, &outsider);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));

    // No approval record should have been created by the rejected call.
    assert!(s.read_release_approval(1_000).is_none());
}

// ─────────────────────────────────────────────────────────
// 2. Default (never-configured) empty signer set must be rejected the same way.
// ─────────────────────────────────────────────────────────

#[test]
fn default_empty_signer_set_is_rejected_identically() {
    let s = TestSetup::new();
    s.lock(1_001, 50_000);

    // `update_multisig_config` is never called in this test, so
    // `get_multisig_config` falls back to its default: `signers: vec![&env]`
    // (an empty vector) and `required_signatures: 0`. Confirm this default is
    // NOT permissive — an arbitrary address must still be rejected.
    let outsider = Address::generate(&s.env);
    let result = s
        .escrow
        .try_approve_large_release(&1_001, &s.contributor, &outsider);

    // Same error as the configured-but-excluded case above: both the "never
    // configured" and the "configured but caller excluded" paths flow through
    // the identical `is_signer` loop in `approve_large_release` (the loop simply
    // finds zero matches either way), so they must produce the identical error.
    assert_eq!(result, Err(Ok(Error::Unauthorized)));
    assert!(s.read_release_approval(1_001).is_none());
}

// ─────────────────────────────────────────────────────────
// 3. Duplicate approval by the same signer must be a strict no-op.
// ─────────────────────────────────────────────────────────

#[test]
fn duplicate_approval_by_same_signer_does_not_double_count() {
    let s = TestSetup::new();
    s.lock(1_002, 50_000);

    let signer_a = Address::generate(&s.env);
    let signer_b = Address::generate(&s.env);

    // Two-of-two multisig: a release should need both distinct signers.
    s.escrow.update_multisig_config(
        &1_i128,
        &vec![&s.env, signer_a.clone(), signer_b.clone()],
        &2,
    );

    // First approval from signer_a is genuine and must be recorded.
    s.escrow
        .approve_large_release(&1_002, &s.contributor, &signer_a);
    let after_first = s
        .read_release_approval(1_002)
        .expect("approval record must exist after first approval");
    assert_eq!(after_first.approvals.len(), 1);
    assert_eq!(after_first.approvals.get(0).unwrap(), signer_a);

    let events_before_repeat = s.env.events().all().len();

    // signer_a approves again on the same bounty — must be a no-op.
    s.escrow
        .approve_large_release(&1_002, &s.contributor, &signer_a);

    let events_after_repeat = s.env.events().all().len();

    // No new event of any kind (in particular no duplicate `ApprovalAdded`) was
    // emitted for the repeat call — exact count diff, not just "an event fired".
    assert_eq!(
        events_after_repeat, events_before_repeat,
        "duplicate approval must not emit a second ApprovalAdded event"
    );

    let after_duplicate = s
        .read_release_approval(1_002)
        .expect("approval record must still exist");
    // approvals length is unchanged: still exactly the one genuine entry from
    // signer_a, not two.
    assert_eq!(after_duplicate.approvals.len(), 1);
    assert_eq!(after_duplicate, after_first);

    // Threshold observation: `required_signatures` is 2, but only ONE distinct
    // signer (signer_a) has ever approved, regardless of how many times they
    // called `approve_large_release`. Note: this contract currently records
    // approvals for informational/bookkeeping purposes only — neither
    // `release_funds` nor `partial_release` reads `ReleaseApproval` or
    // `MultisigConfig` to gate the actual transfer (see FINDING in the PR
    // description). So "not yet approved" is only observable here at the
    // approvals-vec level, which is what we assert:
    let config = s.escrow.get_multisig_config();
    assert_eq!(config.required_signatures, 2);
    assert_eq!(
        after_duplicate.approvals.len(),
        1,
        "signer_a calling twice must not, by itself, reach the 2-signer threshold"
    );

    // A genuine second signer still pushes the count to threshold, proving the
    // vec correctly grows for real distinct approvers (i.e. the no-op above was
    // specific to the duplicate, not a broken push path in general).
    s.escrow
        .approve_large_release(&1_002, &s.contributor, &signer_b);
    let after_second_signer = s.read_release_approval(1_002).unwrap();
    assert_eq!(after_second_signer.approvals.len(), 2);
}

// ─────────────────────────────────────────────────────────
// 4. FINDING (beyond this issue's stated scope, not a required acceptance test):
//    a signer removed via `update_multisig_config` still has their prior
//    approval counted, because `ReleaseApproval.approvals` is never
//    revalidated against the current `MultisigConfig.signers` set.
//
//    This is exploratory recon per issue #316's investigation step, demonstrated
//    here for visibility. It is NOT fixed as part of this test-only issue.
// ─────────────────────────────────────────────────────────

#[test]
fn finding_stale_approval_survives_signer_removal() {
    let s = TestSetup::new();
    s.lock(1_003, 50_000);

    let signer_a = Address::generate(&s.env);
    let signer_b = Address::generate(&s.env);

    // signer_a is a valid signer and approves.
    s.escrow.update_multisig_config(
        &1_i128,
        &vec![&s.env, signer_a.clone(), signer_b.clone()],
        &2,
    );
    s.escrow
        .approve_large_release(&1_003, &s.contributor, &signer_a);
    assert_eq!(s.read_release_approval(1_003).unwrap().approvals.len(), 1);

    // Admin now replaces the signer set, removing signer_a entirely (there is
    // no dedicated "remove signer" entrypoint — `update_multisig_config`
    // wholesale replaces `signers`, which is the only way to drop one).
    s.escrow
        .update_multisig_config(&1_i128, &vec![&s.env, signer_b.clone()], &1);

    let config_after_removal = s.escrow.get_multisig_config();
    assert_eq!(config_after_removal.signers.len(), 1);
    assert_eq!(config_after_removal.signers.get(0).unwrap(), signer_b);

    // FINDING: signer_a's stale approval is still sitting in ReleaseApproval,
    // even though signer_a is no longer a recognized signer at all.
    let approval_after_removal = s.read_release_approval(1_003).unwrap();
    assert_eq!(
        approval_after_removal.approvals.len(),
        1,
        "stale approval from a removed signer is never purged or revalidated"
    );
    assert_eq!(approval_after_removal.approvals.get(0).unwrap(), signer_a);

    // Now the current sole real signer (signer_b) approves once.
    s.escrow
        .approve_large_release(&1_003, &s.contributor, &signer_b);
    let final_approval = s.read_release_approval(1_003).unwrap();

    // approvals now contains BOTH signer_a (removed, stale) and signer_b
    // (current, genuine) — i.e. the removed signer's old approval silently
    // combines with a real signer's approval. If this contract's threshold were
    // ever wired up to gate `release_funds` (it currently is not — see the
    // finding note in `duplicate_approval_by_same_signer_does_not_double_count`),
    // this would let a release proceed on the strength of one *current* signer
    // plus one *removed* signer's leftover approval, rather than requiring two
    // approvals from addresses that are signers *right now*.
    assert_eq!(final_approval.approvals.len(), 2);
    assert!(final_approval.approvals.iter().any(|a| a == signer_a));
    assert!(final_approval.approvals.iter().any(|a| a == signer_b));
}

// ─────────────────────────────────────────────────────────
// 5. ApprovalAdded event payload assertion — single approver.
//
// Drives the *actual* `approve_large_release` entrypoint and
// decodes the emitted event, asserting every field matches the
// inputs. This catches regressions where the event payload
// silently diverges from the applied state (e.g. logging a stale
// contributor address or wrong bounty_id).
// ─────────────────────────────────────────────────────────

#[test]
fn approval_added_event_payload_matches_inputs() {
    use events::{ApprovalAdded, EVENT_VERSION_V2};
    use soroban_sdk::{
        symbol_short,
        testutils::{Events as _, Ledger as _},
        IntoVal, TryFromVal, Val, Vec as SdkVec,
    };

    let s = TestSetup::new();
    let bounty_id: u64 = 2_000;
    s.lock(bounty_id, 50_000);

    let signer = Address::generate(&s.env);
    s.escrow
        .update_multisig_config(&1_i128, &vec![&s.env, signer.clone()], &1);

    let ts_before = s.env.ledger().timestamp();

    s.escrow
        .approve_large_release(&bounty_id, &s.contributor, &signer);

    // Find the ApprovalAdded event by its unique topic ("approval", bounty_id).
    let expected_topics: SdkVec<Val> =
        (symbol_short!("approval"), bounty_id).into_val(&s.env);

    let all = s.env.events().all();
    let mut found = false;
    for i in 0..all.len() {
        let (contract_id, topics, data) = all.get(i).unwrap();
        if contract_id != s.escrow.address {
            continue;
        }
        if topics != expected_topics {
            continue;
        }

        let decoded = ApprovalAdded::try_from_val(&s.env, &data)
            .expect("event data must decode as ApprovalAdded");
        assert_eq!(decoded.version, EVENT_VERSION_V2, "version mismatch");
        assert_eq!(decoded.bounty_id, bounty_id, "bounty_id mismatch");
        assert_eq!(
            decoded.contributor, s.contributor,
            "contributor must match the address passed to approve_large_release"
        );
        assert_eq!(
            decoded.approver, signer,
            "approver must match the signer address"
        );
        assert!(
            decoded.timestamp >= ts_before,
            "timestamp must be >= ledger timestamp at time of call"
        );
        found = true;
        break;
    }
    assert!(found, "ApprovalAdded event was not emitted");
}

// ─────────────────────────────────────────────────────────
// 6. Multiple approvers — each emits a distinct ApprovalAdded
//    event with the correct per-approver payload.
//
// Asserts that N sequential `approve_large_release` calls produce
// exactly N ApprovalAdded events (one per call), with each event's
// `approver` field reflecting the signer that actually called, not
// the first signer or the last signer.
// ─────────────────────────────────────────────────────────

#[test]
fn multiple_approvers_emit_distinct_approval_added_events() {
    use events::{ApprovalAdded, EVENT_VERSION_V2};
    use soroban_sdk::{
        symbol_short,
        testutils::Events as _,
        IntoVal, TryFromVal, Val, Vec as SdkVec,
    };

    let s = TestSetup::new();
    let bounty_id: u64 = 3_000;
    s.lock(bounty_id, 50_000);

    let signer_a = Address::generate(&s.env);
    let signer_b = Address::generate(&s.env);
    let signer_c = Address::generate(&s.env);

    s.escrow.update_multisig_config(
        &1_i128,
        &vec![&s.env, signer_a.clone(), signer_b.clone(), signer_c.clone()],
        &3,
    );

    // Approve sequentially with each signer.
    s.escrow
        .approve_large_release(&bounty_id, &s.contributor, &signer_a);
    s.escrow
        .approve_large_release(&bounty_id, &s.contributor, &signer_b);
    s.escrow
        .approve_large_release(&bounty_id, &s.contributor, &signer_c);

    // Collect all ApprovalAdded events for this bounty.
    let expected_topics: SdkVec<Val> =
        (symbol_short!("approval"), bounty_id).into_val(&s.env);

    let all = s.env.events().all();
    let mut approval_events: soroban_sdk::Vec<ApprovalAdded> = soroban_sdk::Vec::new(&s.env);

    for i in 0..all.len() {
        let (contract_id, topics, data) = all.get(i).unwrap();
        if contract_id != s.escrow.address {
            continue;
        }
        if topics != expected_topics {
            continue;
        }
        let decoded = ApprovalAdded::try_from_val(&s.env, &data)
            .expect("event data must decode as ApprovalAdded");
        approval_events.push_back(decoded);
    }

    // Exactly 3 events — one per distinct approver, not batched.
    assert_eq!(
        approval_events.len(),
        3,
        "expected exactly 3 ApprovalAdded events (one per approver), got {}",
        approval_events.len()
    );

    // Assert each event carries the correct per-approver payload.
    let ev_a = approval_events.get(0).unwrap();
    assert_eq!(ev_a.version, EVENT_VERSION_V2);
    assert_eq!(ev_a.bounty_id, bounty_id);
    assert_eq!(ev_a.contributor, s.contributor);
    assert_eq!(ev_a.approver, signer_a, "first event must be signer_a");

    let ev_b = approval_events.get(1).unwrap();
    assert_eq!(ev_b.version, EVENT_VERSION_V2);
    assert_eq!(ev_b.bounty_id, bounty_id);
    assert_eq!(ev_b.contributor, s.contributor);
    assert_eq!(ev_b.approver, signer_b, "second event must be signer_b");

    let ev_c = approval_events.get(2).unwrap();
    assert_eq!(ev_c.version, EVENT_VERSION_V2);
    assert_eq!(ev_c.bounty_id, bounty_id);
    assert_eq!(ev_c.contributor, s.contributor);
    assert_eq!(ev_c.approver, signer_c, "third event must be signer_c");
}
