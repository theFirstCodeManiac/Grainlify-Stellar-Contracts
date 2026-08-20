#![cfg(test)]

/// # Token-Balance Invariant Test Suite — Program Escrow
///
/// Proves that `remaining_balance` (stored in `ProgramData`) plus the schedule
/// ledger never diverges from the real SAC token balance held by the contract
/// across every payout and release lifecycle path:
///
/// ```text
/// token_client.balance(&contract_id)
///   == spendable_balance + pending_scheduled_amounts
///   == program_data.remaining_balance
/// ```
///
/// ## Covered paths
///
/// 1. `single_payout` — sequential payouts drain `remaining_balance` step-by-step
/// 2. `batch_payout` — batch payouts atomically decrement `remaining_balance`
/// 3. `trigger_program_releases` — automatic schedule bulk-trigger keeps invariant
/// 4. `release_program_schedule_manual` — manual single schedule release
/// 5. `release_prog_schedule_automatic` — automatic single schedule release
/// 6. Insufficient-balance rejection — invariant is untouched on panic
/// 7. Top-up + mixed payouts — `lock_program_funds` top-up followed by mixed paths
use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token, vec, Address, Env, String,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_client(env: &Env) -> (ProgramEscrowContractClient<'static>, Address) {
    let contract_id = env.register_contract(None, ProgramEscrowContract);
    let client = ProgramEscrowContractClient::new(env, &contract_id);
    (client, contract_id)
}

fn make_token(
    env: &Env,
    admin: &Address,
) -> (
    token::Client<'static>,
    token::StellarAssetClient<'static>,
    Address,
) {
    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let token_id = token_contract.address();
    (
        token::Client::new(env, &token_id),
        token::StellarAssetClient::new(env, &token_id),
        token_id,
    )
}

/// Sum all unreleased scheduled amounts from the on-chain schedule ledger.
fn pending_scheduled_total(client: &ProgramEscrowContractClient) -> i128 {
    let schedules = client.get_program_release_schedules(&0, &100);
    let mut total = 0_i128;
    for i in 0..schedules.len() {
        let schedule = schedules.get(i).unwrap();
        if !schedule.released {
            total += schedule.amount;
        }
    }
    total
}

/// Core invariant check: SAC balance held by the contract must equal all
/// accounted funds after every operation. `remaining_balance` is the contract's
/// total accounted balance; splitting it into spendable and unreleased scheduled
/// buckets makes schedule over-reservation fail loudly at the first operation.
fn assert_balance_invariant(
    client: &ProgramEscrowContractClient,
    token_client: &token::Client,
    contract_id: &Address,
    label: &str,
) {
    let sac = token_client.balance(contract_id);
    let remaining = client.get_remaining_balance();
    let pending_scheduled = pending_scheduled_total(client);
    assert!(
        remaining >= pending_scheduled,
        "[{}] INVARIANT VIOLATED — pending schedules ({}) exceed remaining_balance ({})",
        label,
        pending_scheduled,
        remaining,
    );
    let spendable = remaining - pending_scheduled;
    let accounted = spendable + pending_scheduled;
    assert_eq!(
        sac, accounted,
        "[{}] INVARIANT VIOLATED — SAC balance ({}) ≠ spendable ({}) + pending_scheduled ({})",
        label, sac, spendable, pending_scheduled,
    );
}

/// Set up a fully initialized and funded program, returning
/// (client, contract_id, admin, token_client, token_sac_client).
fn setup(
    env: &Env,
    amount: i128,
) -> (
    ProgramEscrowContractClient<'static>,
    Address,
    Address,
    token::Client<'static>,
    token::StellarAssetClient<'static>,
    Address, // token_id
) {
    env.mock_all_auths();
    let (client, contract_id) = make_client(env);
    let admin = Address::generate(env);
    let (token_client, token_sac, token_id) = make_token(env, &admin);
    let program_id = String::from_str(env, "test-program");

    token_sac.mint(&admin, &amount);
    client.init_program(&program_id, &admin, &token_id);
    client.setadmin(&admin);
    if amount > 0 {
        client.lock_program_funds(&admin, &amount);
    }

    (
        client,
        contract_id,
        admin,
        token_client,
        token_sac,
        token_id,
    )
}

// ---------------------------------------------------------------------------
// Test 1 — sequential single_payout drains remaining_balance step-by-step
// ---------------------------------------------------------------------------

#[test]
fn test_invariant_sequential_single_payouts() {
    let env = Env::default();
    let total: i128 = 9_000;
    let (client, contract_id, _admin, token_client, _token_sac, _token_id) = setup(&env, total);

    assert_balance_invariant(&client, &token_client, &contract_id, "initial");

    let w1 = Address::generate(&env);
    let w2 = Address::generate(&env);
    let w3 = Address::generate(&env);

    client.single_payout(&w1, &3_000);
    assert_balance_invariant(&client, &token_client, &contract_id, "after payout 1");
    assert_eq!(client.get_remaining_balance(), 6_000);

    client.single_payout(&w2, &2_500);
    assert_balance_invariant(&client, &token_client, &contract_id, "after payout 2");
    assert_eq!(client.get_remaining_balance(), 3_500);

    client.single_payout(&w3, &3_500);
    assert_balance_invariant(
        &client,
        &token_client,
        &contract_id,
        "after payout 3 (drain)",
    );
    assert_eq!(client.get_remaining_balance(), 0);
    assert_eq!(token_client.balance(&contract_id), 0);
}

// ---------------------------------------------------------------------------
// Test 2 — batch_payout atomically decrements remaining_balance
// ---------------------------------------------------------------------------

#[test]
fn test_invariant_batch_payout() {
    let env = Env::default();
    let total: i128 = 12_000;
    let (client, contract_id, _admin, token_client, _token_sac, _token_id) = setup(&env, total);

    assert_balance_invariant(&client, &token_client, &contract_id, "initial");

    let w1 = Address::generate(&env);
    let w2 = Address::generate(&env);
    let w3 = Address::generate(&env);

    let recipients = vec![&env, w1.clone(), w2.clone(), w3.clone()];
    let amounts = vec![&env, 4_000_i128, 3_000_i128, 5_000_i128];

    client.batch_payout(&recipients, &amounts);
    assert_balance_invariant(&client, &token_client, &contract_id, "after batch payout");
    assert_eq!(client.get_remaining_balance(), 0);
    assert_eq!(token_client.balance(&contract_id), 0);
}

// ---------------------------------------------------------------------------
// Test 3 — trigger_program_releases bulk-triggers due schedules
// ---------------------------------------------------------------------------

#[test]
fn test_invariant_trigger_program_releases() {
    let env = Env::default();
    let total: i128 = 6_000;
    let (client, contract_id, _admin, token_client, _token_sac, _token_id) = setup(&env, total);

    assert_balance_invariant(&client, &token_client, &contract_id, "initial");

    let w1 = Address::generate(&env);
    let w2 = Address::generate(&env);

    // Create two due schedules (release_timestamp = 0, now is also 0)
    client.create_program_release_schedule(&2_000, &0, &w1);
    client.create_program_release_schedule(&4_000, &0, &w2);

    // Invariant still holds — no funds have been transferred yet
    assert_balance_invariant(
        &client,
        &token_client,
        &contract_id,
        "after creating schedules",
    );

    // Trigger all due schedules
    let released = client.trigger_program_releases();
    assert_eq!(released, 2);

    assert_balance_invariant(
        &client,
        &token_client,
        &contract_id,
        "after trigger_program_releases",
    );
    assert_eq!(client.get_remaining_balance(), 0);
    assert_eq!(token_client.balance(&contract_id), 0);
}

// ---------------------------------------------------------------------------
// Test 4 — release_program_schedule_manual keeps invariant
// ---------------------------------------------------------------------------

#[test]
fn test_invariant_release_program_schedule_manual() {
    let env = Env::default();
    let total: i128 = 8_000;
    let (client, contract_id, _admin, token_client, _token_sac, _token_id) = setup(&env, total);

    assert_balance_invariant(&client, &token_client, &contract_id, "initial");

    let w1 = Address::generate(&env);
    let w2 = Address::generate(&env);

    // Create two schedules (release_timestamp = 0 so they are immediately eligible)
    let sched1 = client.create_program_release_schedule(&3_000, &0, &w1);
    let sched2 = client.create_program_release_schedule(&5_000, &0, &w2);

    assert_balance_invariant(
        &client,
        &token_client,
        &contract_id,
        "after creating schedules",
    );

    // Release first schedule manually
    client.release_program_schedule_manual(&sched1.schedule_id);
    assert_balance_invariant(
        &client,
        &token_client,
        &contract_id,
        "after manual release 1",
    );
    assert_eq!(client.get_remaining_balance(), 5_000);

    // Release second schedule manually
    client.release_program_schedule_manual(&sched2.schedule_id);
    assert_balance_invariant(
        &client,
        &token_client,
        &contract_id,
        "after manual release 2",
    );
    assert_eq!(client.get_remaining_balance(), 0);
    assert_eq!(token_client.balance(&contract_id), 0);
}

// ---------------------------------------------------------------------------
// Test 5 — release_prog_schedule_automatic keeps invariant
// ---------------------------------------------------------------------------

#[test]
fn test_invariant_release_prog_schedule_automatic() {
    let env = Env::default();
    let total: i128 = 5_000;
    let (client, contract_id, _admin, token_client, _token_sac, _token_id) = setup(&env, total);

    assert_balance_invariant(&client, &token_client, &contract_id, "initial");

    let winner = Address::generate(&env);

    // Create a schedule with release_timestamp = 100
    let sched = client.create_program_release_schedule(&5_000, &100, &winner);

    assert_balance_invariant(
        &client,
        &token_client,
        &contract_id,
        "after creating schedule",
    );

    // Advance ledger timestamp past release point
    env.ledger().set_timestamp(200);

    client.release_prog_schedule_automatic(&sched.schedule_id);
    assert_balance_invariant(
        &client,
        &token_client,
        &contract_id,
        "after automatic release",
    );
    assert_eq!(client.get_remaining_balance(), 0);
    assert_eq!(token_client.balance(&contract_id), 0);
}

// ---------------------------------------------------------------------------
// Test 6 — over-payout attempt panics; invariant is preserved
// ---------------------------------------------------------------------------

#[test]
fn test_invariant_overpayout_rejected() {
    let env = Env::default();
    let total: i128 = 1_000;
    let (client, contract_id, _admin, token_client, _token_sac, _token_id) = setup(&env, total);

    assert_balance_invariant(&client, &token_client, &contract_id, "initial");

    let winner = Address::generate(&env);

    // Attempt a payout exceeding available funds — should panic
    let result = client.try_single_payout(&winner, &2_000);
    assert!(result.is_err(), "expected over-payout to fail");

    // Invariant must still hold after the rejected call
    assert_balance_invariant(
        &client,
        &token_client,
        &contract_id,
        "after rejected over-payout",
    );
    assert_eq!(client.get_remaining_balance(), total);
}

// ---------------------------------------------------------------------------
// Test 7 — top-up via lock_program_funds then mixed payout paths
// ---------------------------------------------------------------------------

#[test]
fn test_invariant_topup_then_mixed_payouts() {
    let env = Env::default();
    let initial: i128 = 5_000;
    let topup: i128 = 3_000;
    let (client, contract_id, admin, token_client, token_sac, _token_id) = setup(&env, initial);

    assert_balance_invariant(&client, &token_client, &contract_id, "after initial lock");

    // Top up with additional funds
    token_sac.mint(&admin, &topup);
    client.lock_program_funds(&admin, &topup);
    assert_balance_invariant(&client, &token_client, &contract_id, "after top-up");
    assert_eq!(client.get_remaining_balance(), initial + topup);

    let w1 = Address::generate(&env);
    let w2 = Address::generate(&env);
    let w3 = Address::generate(&env);

    // Mix 1: single payout
    client.single_payout(&w1, &2_000);
    assert_balance_invariant(&client, &token_client, &contract_id, "after single_payout");

    // Mix 2: batch payout
    let recipients = vec![&env, w2.clone()];
    let amounts = vec![&env, 3_000_i128];
    client.batch_payout(&recipients, &amounts);
    assert_balance_invariant(&client, &token_client, &contract_id, "after batch_payout");

    // Mix 3: manual schedule release
    let sched = client.create_program_release_schedule(&3_000, &0, &w3);
    client.release_program_schedule_manual(&sched.schedule_id);
    assert_balance_invariant(
        &client,
        &token_client,
        &contract_id,
        "after manual schedule release",
    );
    assert_eq!(client.get_remaining_balance(), 0);
    assert_eq!(token_client.balance(&contract_id), 0);
}

// ---------------------------------------------------------------------------
// Test 8 — deterministic mixed sequence with schedules, disputes, and logging
// ---------------------------------------------------------------------------

#[test]
fn test_reconciliation_invariant_after_each_mixed_operation() {
    let env = Env::default();
    let total: i128 = 20_000;
    let (client, contract_id, _admin, token_client, _token_sac, _token_id) = setup(&env, total);

    let w1 = Address::generate(&env);
    let w2 = Address::generate(&env);
    let w3 = Address::generate(&env);
    let w4 = Address::generate(&env);

    assert_balance_invariant(&client, &token_client, &contract_id, "sequence=start");

    client.single_payout(&w1, &1_000);
    assert_balance_invariant(
        &client,
        &token_client,
        &contract_id,
        "sequence=single_payout(1000)",
    );

    // Partial batch spend: leaves both spendable funds and later scheduled funds
    // in the same contract balance.
    let batch_recipients = vec![&env, w2.clone(), w3.clone()];
    let batch_amounts = vec![&env, 1_500_i128, 2_500_i128];
    client.batch_payout(&batch_recipients, &batch_amounts);
    assert_balance_invariant(
        &client,
        &token_client,
        &contract_id,
        "sequence=batch_payout(1500,2500)",
    );

    let sched1 = client.create_program_release_schedule(&3_000, &50, &w1);
    let _sched2 = client.create_program_release_schedule(&4_000, &100, &w4);
    assert_balance_invariant(
        &client,
        &token_client,
        &contract_id,
        "sequence=create_schedules(3000@50,4000@100)",
    );

    // Automatic release before due time must fail without changing accounting.
    env.ledger().set_timestamp(49);
    let early = client.try_release_prog_schedule_automatic(&sched1.schedule_id);
    assert!(early.is_err(), "expected before-due release to fail");
    assert_balance_invariant(
        &client,
        &token_client,
        &contract_id,
        "sequence=failed_automatic_release_before_due(schedule=1)",
    );

    // Due exactly at the scheduled timestamp.
    env.ledger().set_timestamp(50);
    client.release_prog_schedule_automatic(&sched1.schedule_id);
    assert_balance_invariant(
        &client,
        &token_client,
        &contract_id,
        "sequence=automatic_release_due_exactly(schedule=1)",
    );

    // Open dispute blocks payout/release paths and must preserve the invariant.
    client.open_dispute(&String::from_str(
        &env,
        "pause payouts while reviewing award",
    ));
    let disputed_payout = client.try_single_payout(&w2, &500);
    assert!(disputed_payout.is_err(), "expected disputed payout to fail");
    let disputed_release = client.try_trigger_program_releases();
    assert!(
        disputed_release.is_err(),
        "expected disputed schedule trigger to fail"
    );
    assert_balance_invariant(
        &client,
        &token_client,
        &contract_id,
        "sequence=dispute_blocked_payout_and_release",
    );

    client.resolve_dispute();
    env.ledger().set_timestamp(100);
    let released = client.trigger_program_releases();
    assert_eq!(released, 1);
    assert_balance_invariant(
        &client,
        &token_client,
        &contract_id,
        "sequence=resolve_dispute_then_trigger_due(schedule=2)",
    );

    client.single_payout(&w3, &8_000);
    assert_balance_invariant(
        &client,
        &token_client,
        &contract_id,
        "sequence=final_single_payout(8000)",
    );
    assert_eq!(client.get_remaining_balance(), 0);
    assert_eq!(pending_scheduled_total(&client), 0);
    assert_eq!(token_client.balance(&contract_id), 0);
}

// ---------------------------------------------------------------------------
// Test A — incremental milestone claims maintain invariant
// ---------------------------------------------------------------------------

#[test]
fn test_invariant_incremental_milestone_claims() {
    let env = Env::default();
    let total: i128 = 9_000;
    let (client, contract_id, _admin, token_client, _token_sac, _token_id) = setup(&env, total);

    // Create three equal milestones
    let w1 = Address::generate(&env);
    let w2 = Address::generate(&env);
    let w3 = Address::generate(&env);
    let sched1 = client.create_program_release_schedule(&3_000, &0, &w1);
    let sched2 = client.create_program_release_schedule(&3_000, &0, &w2);
    let sched3 = client.create_program_release_schedule(&3_000, &0, &w3);

    assert_balance_invariant(&client, &token_client, &contract_id, "initial");

    client.release_program_schedule_manual(&sched1.schedule_id);
    assert_balance_invariant(&client, &token_client, &contract_id, "after claim 1");

    client.release_program_schedule_manual(&sched2.schedule_id);
    assert_balance_invariant(&client, &token_client, &contract_id, "after claim 2");

    client.release_program_schedule_manual(&sched3.schedule_id);
    assert_balance_invariant(&client, &token_client, &contract_id, "after claim 3");

    assert_eq!(client.get_remaining_balance(), 0);
}

// ---------------------------------------------------------------------------
// Test B — double‑claim of a milestone is rejected and does not affect balance
// ---------------------------------------------------------------------------

#[test]
fn test_invariant_double_claim_milestone_rejected() {
    let env = Env::default();
    let total: i128 = 5_000;
    let (client, contract_id, _admin, token_client, _token_sac, _token_id) = setup(&env, total);

    let winner = Address::generate(&env);
    let sched = client.create_program_release_schedule(&total, &0, &winner);
    assert_balance_invariant(&client, &token_client, &contract_id, "initial");

    // First release succeeds
    client.release_program_schedule_manual(&sched.schedule_id);
    let bal_after_first = token_client.balance(&winner);

    // Second attempt should fail
    let res = client.try_release_program_schedule_manual(&sched.schedule_id);
    assert!(res.is_err(), "double‑claim must be rejected");

    let bal_after_second = token_client.balance(&winner);
    assert_eq!(
        bal_after_second, bal_after_first,
        "balance must not change after double‑claim"
    );

    // Invariant still holds
    assert_balance_invariant(
        &client,
        &token_client,
        &contract_id,
        "after double‑claim attempt",
    );
}

// ---------------------------------------------------------------------------
// Test C — out‑of‑order milestone releases keep invariant (contract permits independent releases)
// ---------------------------------------------------------------------------

#[test]
fn test_invariant_out_of_order_milestone_claims() {
    let env = Env::default();
    let total: i128 = 9_000;
    let (client, contract_id, _admin, token_client, _token_sac, _token_id) = setup(&env, total);

    let w1 = Address::generate(&env);
    let w2 = Address::generate(&env);
    let w3 = Address::generate(&env);
    let sched1 = client.create_program_release_schedule(&3_000, &0, &w1);
    let sched2 = client.create_program_release_schedule(&3_000, &0, &w2);
    let sched3 = client.create_program_release_schedule(&3_000, &0, &w3);

    assert_balance_invariant(&client, &token_client, &contract_id, "initial");

    // Release milestone 2 first
    client.release_program_schedule_manual(&sched2.schedule_id);
    assert_balance_invariant(&client, &token_client, &contract_id, "after claim 2");

    // Release milestone 1 next
    client.release_program_schedule_manual(&sched1.schedule_id);
    assert_balance_invariant(&client, &token_client, &contract_id, "after claim 1");

    // Release milestone 3 finally
    client.release_program_schedule_manual(&sched3.schedule_id);
    assert_balance_invariant(&client, &token_client, &contract_id, "after claim 3");

    assert_eq!(client.get_remaining_balance(), 0);
}
