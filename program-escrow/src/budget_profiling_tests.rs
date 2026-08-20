#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Events, Ledger},
    token, vec, Address, Env, Map, String, Symbol, TryFromVal, Val, Vec,
};
use std::println;

// ============================================================================
// Shared constants
// ============================================================================

const PAYOUT_AMOUNT: i128 = 1_000;
const INITIAL_FUNDS: i128 = 10_000_000;

// ============================================================================
// Hard ceilings (absolute maximum)
//
// These guard against catastrophic regressions that would push a transaction
// over Soroban's per-transaction budget limit in production.  They sit well
// above the measured baselines to allow for legitimate feature growth, but
// below Soroban's hard per-transaction limits.
// ============================================================================

const SINGLE_PAYOUT_CPU_CEILING: u64 = 2_000_000;
const SINGLE_PAYOUT_MEM_CEILING: u64 = 500_000;
const TRIGGER_RELEASES_CPU_CEILING: u64 = 10_000_000;
const TRIGGER_RELEASES_MEM_CEILING: u64 = 2_000_000;
// batch ceiling formula: BATCH_BASE_*_CEILING + batch_size * BATCH_PER_RECIPIENT_*_CEILING
const BATCH_BASE_CPU_CEILING: u64 = 500_000;
const BATCH_PER_RECIPIENT_CPU_CEILING: u64 = 300_000;
const BATCH_BASE_MEM_CEILING: u64 = 200_000;
const BATCH_PER_RECIPIENT_MEM_CEILING: u64 = 55_000;

// ============================================================================
// Regression-threshold baselines
//
// These represent the *expected* instruction/memory cost measured against the
// current implementation.  Together with REGRESSION_MARGIN_PCT they form a
// tighter guard than the hard ceilings: a change that silently doubles the
// cost of single_payout will fail here long before it hits the ceiling.
//
// Baselines were measured with soroban-sdk v21.7.7 / soroban-env-host v21.2.1
// on 2026-07-21.  The batch baseline uses a linear model fit to size=1..100:
//   cpu_expected ≈ BATCH_BASE + batch_size * BATCH_PER_RECIPIENT
//
// --- How to update these baselines -------------------------------------------
// If a legitimate feature addition raises instruction cost, update the
// relevant constant below to the new measured value and add a comment
// explaining why the cost increased.  This is a deliberate, one-line change
// that makes the regression visible in code review.
//
// Example:
//   // Increased from 430_000 after adding whitelist enforcement check (#NNN)
//   const SINGLE_PAYOUT_CPU_BASELINE: u64 = 510_000;
// =============================================================================

/// Allowed percentage increase over a baseline before the test fails.
/// 15% gives room for minor SDK/host fluctuations while catching genuine
/// regressions.  Must be updated intentionally when cost legitimately grows.
const REGRESSION_MARGIN_PCT: u64 = 15;

// single_payout baselines (measured: cpu=430_561, mem=69_853)
const SINGLE_PAYOUT_CPU_BASELINE: u64 = 430_561;
const SINGLE_PAYOUT_MEM_BASELINE: u64 = 69_853;

// trigger_program_releases baselines, 10 schedules (measured: cpu=2_579_247, mem=418_001)
const TRIGGER_RELEASES_CPU_BASELINE: u64 = 2_579_247;
const TRIGGER_RELEASES_MEM_BASELINE: u64 = 418_001;

// batch_payout base (fixed per-call overhead) baselines
// Linear model fitted to size=1..100 measurements.
// cpu: base=210_000, per_recipient=235_000 (all measured sizes fit within +15%)
// mem: base=25_000,  per_recipient=46_000
const BATCH_BASE_CPU_BASELINE: u64 = 210_000;
const BATCH_BASE_MEM_BASELINE: u64 = 25_000;

// batch_payout per-recipient marginal cost baselines
const BATCH_PER_RECIPIENT_CPU_BASELINE: u64 = 235_000;
const BATCH_PER_RECIPIENT_MEM_BASELINE: u64 = 46_000;

// ============================================================================
// Internal types
// ============================================================================

// ============================================================================
// Helpers
// ============================================================================

#[derive(Clone, Copy, Debug)]
struct BudgetSample {
    cpu: u64,
    mem: u64,
}

// ============================================================================
// Test helpers
// ============================================================================

fn setup_program(env: &Env, initial_amount: i128) -> ProgramEscrowContractClient<'static> {
    env.mock_all_auths();

    let contract_id = env.register_contract(None, ProgramEscrowContract);
    let client = ProgramEscrowContractClient::new(env, &contract_id);

    let admin = Address::generate(env);
    let token_admin = Address::generate(env);
    let token_contract = env.register_stellar_asset_contract_v2(token_admin.clone());
    let token_id = token_contract.address();
    let token_admin_client = token::StellarAssetClient::new(env, &token_id);
    let program_id = String::from_str(env, "budget-profile");

    client.init_program(&program_id, &admin, &token_id);
    token_admin_client.mint(&admin, &initial_amount);
    client.lock_program_funds(&admin, &initial_amount);

    client
}

fn reset_budget(env: &Env) {
    let mut budget = env.budget();
    budget.reset_default();
}

fn budget_sample(env: &Env) -> BudgetSample {
    let budget = env.budget();
    BudgetSample {
        cpu: budget.cpu_instruction_cost(),
        mem: budget.memory_bytes_cost(),
    }
}

fn batch_vectors(env: &Env, batch_size: u32) -> (Vec<Address>, Vec<i128>) {
    let mut recipients = vec![env];
    let mut amounts = vec![env];

    for _ in 0..batch_size {
        recipients.push_back(Address::generate(env));
        amounts.push_back(PAYOUT_AMOUNT);
    }

    (recipients, amounts)
}

fn measure_batch_payout(batch_size: u32) -> BudgetSample {
    let env = Env::default();
    let client = setup_program(&env, INITIAL_FUNDS);
    let (recipients, amounts) = batch_vectors(&env, batch_size);

    reset_budget(&env);
    client.batch_payout(&recipients, &amounts);
    budget_sample(&env)
}

fn get_u32_event_field(env: &Env, data: &Val, field: &str) -> Option<u32> {
    let data_map: Map<Symbol, Val> = Map::try_from_val(env, data).ok()?;
    let field_val = data_map.get(Symbol::new(env, field))?;
    u32::try_from_val(env, &field_val).ok()
}

fn latest_batch_gas_proxy_metrics(
    env: &Env,
    client: &ProgramEscrowContractClient<'_>,
) -> Option<(u32, u32, u32, u32, u32)> {
    let events = env.events().all();

    for (contract, _topics, data) in events.iter().rev() {
        if contract != client.address {
            continue;
        }

        let transfer_ops = get_u32_event_field(env, &data, "gas_proxy_transfer_ops");
        let history_appends = get_u32_event_field(env, &data, "gas_proxy_history_appends");
        let storage_reads = get_u32_event_field(env, &data, "gas_proxy_storage_reads");
        let storage_writes = get_u32_event_field(env, &data, "gas_proxy_storage_writes");
        let events_emitted = get_u32_event_field(env, &data, "gas_proxy_events_emitted");

        if let (
            Some(transfer_ops),
            Some(history_appends),
            Some(storage_reads),
            Some(storage_writes),
            Some(events_emitted),
        ) = (
            transfer_ops,
            history_appends,
            storage_reads,
            storage_writes,
            events_emitted,
        ) {
            return Some((
                transfer_ops,
                history_appends,
                storage_reads,
                storage_writes,
                events_emitted,
            ));
        }
    }

    None
}

/// Assert that `actual` does not exceed `baseline` by more than
/// `REGRESSION_MARGIN_PCT` percent, and also stays under `ceiling`.
///
/// Fails with a clear message naming the metric, the actual value, the
/// threshold, and the baseline so the developer immediately knows what to
/// update.
///
/// # Updating baselines
/// When a legitimate feature increases cost, update the corresponding
/// `*_BASELINE` constant at the top of this file and add a comment explaining
/// why. This keeps the regression visible in code review as a deliberate,
/// one-line change.
fn assert_within_regression_threshold(label: &str, actual: u64, baseline: u64, ceiling: u64) {
    // threshold = baseline * (1 + REGRESSION_MARGIN_PCT / 100)
    let threshold = baseline + (baseline * REGRESSION_MARGIN_PCT / 100);

    println!(
        "[budget] {label}: actual={actual} baseline={baseline} \
         threshold={threshold} (+{REGRESSION_MARGIN_PCT}%) ceiling={ceiling}"
    );

    assert!(
        actual > 0,
        "[budget] {label}: measured cost is zero — budget tracking may not be active"
    );
    assert!(
        actual <= threshold,
        "[budget] REGRESSION in {label}: actual={actual} exceeds regression threshold={threshold} \
         (baseline={baseline} + {REGRESSION_MARGIN_PCT}%). \
         If this increase is intentional, update the baseline constant in \
         budget_profiling_tests.rs and add a comment explaining why."
    );
    assert!(
        actual <= ceiling,
        "[budget] {label}: actual={actual} exceeds hard ceiling={ceiling}"
    );
}

// ============================================================================
// Profiling tests
// ============================================================================

#[test]
fn budget_profiling_batch_payout_scales_linearly_to_max_batch_size() {
    let samples = [
        (1_u32, measure_batch_payout(1)),
        (10_u32, measure_batch_payout(10)),
        (50_u32, measure_batch_payout(50)),
        (MAX_BATCH_SIZE, measure_batch_payout(MAX_BATCH_SIZE)),
    ];

    for (batch_size, sample) in samples {
        let cpu_ceiling =
            BATCH_BASE_CPU_CEILING + (batch_size as u64 * BATCH_PER_RECIPIENT_CPU_CEILING);
        let mem_ceiling =
            BATCH_BASE_MEM_CEILING + (batch_size as u64 * BATCH_PER_RECIPIENT_MEM_CEILING);

        let cpu_baseline =
            BATCH_BASE_CPU_BASELINE + (batch_size as u64 * BATCH_PER_RECIPIENT_CPU_BASELINE);
        let mem_baseline =
            BATCH_BASE_MEM_BASELINE + (batch_size as u64 * BATCH_PER_RECIPIENT_MEM_BASELINE);

        println!(
            "batch_payout size={batch_size} cpu={} mem={}",
            sample.cpu, sample.mem
        );

        assert_within_regression_threshold(
            &std::format!("batch_payout(cpu, size={batch_size})"),
            sample.cpu,
            cpu_baseline,
            cpu_ceiling,
        );
        assert_within_regression_threshold(
            &std::format!("batch_payout(mem, size={batch_size})"),
            sample.mem,
            mem_baseline,
            mem_ceiling,
        );
    }
}

#[test]
fn budget_profiling_single_payout_and_trigger_releases_stay_under_regression_ceiling() {
    // --- single_payout -------------------------------------------------------
    let env_single = Env::default();
    let single_client = setup_program(&env_single, INITIAL_FUNDS);
    let recipient = Address::generate(&env_single);

    reset_budget(&env_single);
    single_client.single_payout(&recipient, &PAYOUT_AMOUNT);
    let single = budget_sample(&env_single);
    println!("single_payout cpu={} mem={}", single.cpu, single.mem);

    assert_within_regression_threshold(
        "single_payout(cpu)",
        single.cpu,
        SINGLE_PAYOUT_CPU_BASELINE,
        SINGLE_PAYOUT_CPU_CEILING,
    );
    assert_within_regression_threshold(
        "single_payout(mem)",
        single.mem,
        SINGLE_PAYOUT_MEM_BASELINE,
        SINGLE_PAYOUT_MEM_CEILING,
    );

    // --- trigger_program_releases (10 schedules) ----------------------------
    let env_release = Env::default();
    let release_client = setup_program(&env_release, INITIAL_FUNDS);
    let release_at = env_release.ledger().timestamp().saturating_add(10);

    for _ in 0..10 {
        release_client.create_program_release_schedule(
            &PAYOUT_AMOUNT,
            &release_at,
            &Address::generate(&env_release),
        );
    }
    env_release.ledger().set_timestamp(release_at);

    reset_budget(&env_release);
    let released = release_client.trigger_program_releases();
    let trigger = budget_sample(&env_release);
    println!(
        "trigger_program_releases count={released} cpu={} mem={}",
        trigger.cpu, trigger.mem
    );

    assert_eq!(released, 10);
    assert_within_regression_threshold(
        "trigger_program_releases(cpu, schedules=10)",
        trigger.cpu,
        TRIGGER_RELEASES_CPU_BASELINE,
        TRIGGER_RELEASES_CPU_CEILING,
    );
    assert_within_regression_threshold(
        "trigger_program_releases(mem, schedules=10)",
        trigger.mem,
        TRIGGER_RELEASES_MEM_BASELINE,
        TRIGGER_RELEASES_MEM_CEILING,
    );
}

#[test]
fn budget_profiling_gas_proxy_fields_match_operation_counts() {
    let env = Env::default();
    let client = setup_program(&env, INITIAL_FUNDS);
    let batch_size = 7_u32;
    let (recipients, amounts) = batch_vectors(&env, batch_size);

    let data = client.batch_payout(&recipients, &amounts);
    let (transfer_ops, history_appends, storage_reads, storage_writes, events_emitted) =
        latest_batch_gas_proxy_metrics(&env, &client).expect("batch gas proxy metrics missing");

    assert_eq!(data.payout_history.len(), batch_size);
    assert_eq!(transfer_ops, batch_size);
    assert_eq!(history_appends, batch_size);
    assert_eq!(storage_reads, 1);
    assert_eq!(storage_writes, 1);
    assert_eq!(events_emitted, 1);
}

#[test]
#[should_panic(expected = "All amounts must be greater than zero")]
fn budget_profiling_zero_amount_batch_is_still_rejected() {
    let env = Env::default();
    let client = setup_program(&env, INITIAL_FUNDS);
    let recipients = vec![&env, Address::generate(&env)];
    let amounts = vec![&env, 0_i128];

    reset_budget(&env);
    client.batch_payout(&recipients, &amounts);
}

// ============================================================================
// Regression-threshold unit tests
//
// These exercise assert_within_regression_threshold in isolation so failures
// in the helper itself are immediately obvious and do not require a full
// contract invocation to diagnose.
// ============================================================================

/// Confirms that assert_within_regression_threshold passes when actual equals
/// the baseline (zero regression).
#[test]
fn regression_threshold_passes_at_baseline() {
    // actual == baseline — should always pass
    assert_within_regression_threshold("unit_test(at_baseline)", 100_000, 100_000, 1_000_000);
}

/// Confirms that assert_within_regression_threshold passes when actual is
/// exactly at the margin boundary (baseline + 15%).
#[test]
fn regression_threshold_passes_at_margin_boundary() {
    let baseline: u64 = 100_000;
    let at_boundary = baseline + (baseline * REGRESSION_MARGIN_PCT / 100); // 115_000
    assert_within_regression_threshold(
        "unit_test(at_margin_boundary)",
        at_boundary,
        baseline,
        1_000_000,
    );
}

/// Confirms that assert_within_regression_threshold fails when actual exceeds
/// the margin by even one instruction.
#[test]
#[should_panic(expected = "REGRESSION")]
fn regression_threshold_fails_one_over_margin() {
    let baseline: u64 = 100_000;
    let one_over = baseline + (baseline * REGRESSION_MARGIN_PCT / 100) + 1; // 115_001
    assert_within_regression_threshold("unit_test(one_over_margin)", one_over, baseline, 1_000_000);
}

/// Confirms that assert_within_regression_threshold fails when actual is well
/// over the margin (simulates a doubling of instruction cost).
#[test]
#[should_panic(expected = "REGRESSION")]
fn regression_threshold_fails_on_significant_regression() {
    let baseline: u64 = 100_000;
    let doubled = baseline * 2; // 200% — far beyond the 15% margin
    assert_within_regression_threshold("unit_test(doubled_cost)", doubled, baseline, 1_000_000);
}
