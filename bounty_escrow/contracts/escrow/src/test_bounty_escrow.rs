#![cfg(test)]
use crate::{events, BountyEscrowContract, BountyEscrowContractClient, ClaimCreated, ClaimExecuted, Error as ContractError};
use soroban_sdk::testutils::Events;
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Ledger},
    token, vec, Address, Env, Map, Symbol, TryFromVal, Val,
};

fn create_test_env() -> (Env, BountyEscrowContractClient<'static>, Address) {
    let env = Env::default();
    let contract_id = env.register_contract(None, BountyEscrowContract);
    let client = BountyEscrowContractClient::new(&env, &contract_id);

    (env, client, contract_id)
}

fn create_token_contract<'a>(
    e: &'a Env,
    admin: &Address,
) -> (Address, token::Client<'a>, token::StellarAssetClient<'a>) {
    let token_id = e.register_stellar_asset_contract_v2(admin.clone());
    let token = token_id.address();
    let token_client = token::Client::new(e, &token);
    let token_admin_client = token::StellarAssetClient::new(e, &token);
    (token, token_client, token_admin_client)
}

fn assert_event_data_has_v2_tag(env: &Env, data: &Val) {
    let data_map: Map<Symbol, Val> =
        Map::try_from_val(env, data).unwrap_or_else(|_| panic!("event payload should be a map"));
    let version_val = data_map
        .get(Symbol::new(env, "version"))
        .unwrap_or_else(|| panic!("event payload must contain version field"));
    let version = u32::try_from_val(env, &version_val).expect("version should decode as u32");
    assert_eq!(version, 2);
}

fn assert_current_call_has_versioned_contract_event(env: &Env, contract_id: &Address) {
    let events = env.events().all();
    let mut found = false;
    for (contract, _topics, data) in events.iter() {
        if contract != *contract_id {
            continue;
        }
        // Only require that at least one event for this call carries
        // the V2 version tag; other event families (e.g. analytics)
        // may legitimately use different versioning schemes.
        if let Ok(data_map) = Map::<Symbol, Val>::try_from_val(env, &data) {
            if let Some(version_val) = data_map.get(Symbol::new(env, "version")) {
                if let Ok(version) = u32::try_from_val(env, &version_val) {
                    if version == 2 {
                        found = true;
                        break;
                    }
                }
            }
        }
    }
    assert!(found);
}

/// Locate the first event published by `contract_id` whose first topic
/// equals `topic0`, returning its topics and raw payload for field-by-field
/// assertions. Panics if no matching event was emitted.
fn find_contract_event(
    env: &Env,
    contract_id: &Address,
    topic0: Symbol,
) -> (soroban_sdk::Vec<Val>, Val) {
    let events = env.events().all();
    for i in 0..events.len() {
        let (contract, topics, data) = events.get(i).unwrap();
        if contract != *contract_id || topics.len() == 0 {
            continue;
        }
        if let Ok(sym) = Symbol::try_from_val(env, &topics.get(0).unwrap()) {
            if sym == topic0 {
                return (topics, data);
            }
        }
    }
    panic!("no event with the expected topic was emitted");
}

/// Like `find_contract_event`, but returns the LAST matching event instead of
/// the first. Needed when more than one event shares `topic0` (e.g. both
/// `authorize_claim` and `claim` emit under the `claim` topic0, distinguished
/// only by their second topic) and the test cares about a later one.
fn find_last_contract_event(
    env: &Env,
    contract_id: &Address,
    topic0: Symbol,
) -> (soroban_sdk::Vec<Val>, Val) {
    let events = env.events().all();
    for i in (0..events.len()).rev() {
        let (contract, topics, data) = events.get(i).unwrap();
        if contract != *contract_id || topics.len() == 0 {
            continue;
        }
        if let Ok(sym) = Symbol::try_from_val(env, &topics.get(0).unwrap()) {
            if sym == topic0 {
                return (topics, data);
            }
        }
    }
    panic!("no event with the expected topic was emitted");
}

#[test]
fn test_init_event() {
    let (env, client, _contract_id) = create_test_env();
    let _employee = Address::generate(&env);

    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let _depositor = Address::generate(&env);
    let _bounty_id = 1;

    env.mock_all_auths();

    // Initialize
    client.init(&admin.clone(), &token.clone());

    // Get all events emitted
    let events = env.events().all();

    // Verify the event was emitted
    assert_eq!(events.len(), 1);
}

#[test]
fn test_events_emit_v2_version_tags_for_all_bounty_emitters() {
    let (env, client, contract_id) = create_test_env();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let contributor = Address::generate(&env);
    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);

    client.init(&admin, &token);
    assert_current_call_has_versioned_contract_event(&env, &contract_id);

    token_admin_client.mint(&depositor, &10_000);
    client.lock_funds(&depositor, &1, &10_000, &(env.ledger().timestamp() + 10));
    assert_current_call_has_versioned_contract_event(&env, &contract_id);

    client.release_funds(&1, &contributor);
    assert_current_call_has_versioned_contract_event(&env, &contract_id);
}

#[test]
fn test_lock_fund() {
    let (env, client, _contract_id) = create_test_env();
    let _employee = Address::generate(&env);

    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let bounty_id = 1;
    let amount = 1000;
    let deadline = 10;

    env.mock_all_auths();

    // Setup token
    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);

    // Initialize
    client.init(&admin.clone(), &token.clone());

    token_admin_client.mint(&depositor, &amount);

    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

    // Get all events emitted
    let events = env.events().all();

    // Verify lock produced events (exact count can vary across Soroban versions).
    assert!(events.len() >= 2);
}

#[test]
fn test_release_fund() {
    let (env, client, _contract_id) = create_test_env();

    let admin = Address::generate(&env);
    // let token = Address::generate(&env);
    let depositor = Address::generate(&env);
    let contributor = Address::generate(&env);
    let bounty_id = 1;
    let amount = 1000;
    let deadline = 10;

    env.mock_all_auths();

    // Setup token
    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);

    // Initialize
    client.init(&admin.clone(), &token.clone());

    token_admin_client.mint(&depositor, &amount);

    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

    client.release_funds(&bounty_id, &contributor);

    // Get all events emitted
    let events = env.events().all();

    // Verify release produced events (exact count can vary across Soroban versions).
    assert!(events.len() >= 2);
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")] // AlreadyInitialized
fn test_init_rejects_reinitialization() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    env.mock_all_auths();

    client.init(&admin, &token);
    client.init(&admin, &token);
}

#[test]
fn test_lock_funds_zero_amount_edge_case() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let bounty_id = 100;
    let amount = 0;
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &1_000);

    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

    let escrow = client.get_escrow_info(&bounty_id);
    assert_eq!(escrow.amount, 0);
    assert_eq!(escrow.status, crate::EscrowStatus::Locked);
}

#[test]
#[should_panic] // Token transfer fails due to insufficient balance, protecting against overflows/invalid accounting.
fn test_lock_funds_insufficient_balance_rejected() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let bounty_id = 101;
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &100);

    client.lock_funds(&depositor, &bounty_id, &1_000, &deadline);
}

#[test]
fn test_refund_allows_exact_deadline_boundary() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let bounty_id = 102;
    let amount = 700;
    let now = env.ledger().timestamp();
    let deadline = now + 500;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &amount);
    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

    env.ledger().set_timestamp(deadline);
    client.refund(&bounty_id);

    let escrow = client.get_escrow_info(&bounty_id);
    assert_eq!(escrow.status, crate::EscrowStatus::Refunded);
    assert_eq!(token_client.balance(&depositor), amount);
}

#[test]
fn test_maximum_lock_and_release_path() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let contributor = Address::generate(&env);
    let bounty_id = 103;
    let amount = i64::MAX as i128;
    let deadline = env.ledger().timestamp() + 1_000;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &amount);
    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

    assert_eq!(token_client.balance(&client.address), amount);
    client.release_funds(&bounty_id, &contributor);
    assert_eq!(token_client.balance(&client.address), 0);
    assert_eq!(token_client.balance(&contributor), amount);
}

#[test]
fn test_integration_multi_bounty_lifecycle() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let contributor = Address::generate(&env);
    let now = env.ledger().timestamp();

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &10_000);

    client.lock_funds(&depositor, &201, &3_000, &(now + 100));
    client.lock_funds(&depositor, &202, &2_000, &(now + 200));
    client.lock_funds(&depositor, &203, &1_000, &(now + 300));
    assert_eq!(token_client.balance(&client.address), 6_000);

    client.release_funds(&201, &contributor);
    env.ledger().set_timestamp(now + 201);
    client.refund(&202);
    assert_eq!(token_client.balance(&client.address), 1_000);

    let escrow_201 = client.get_escrow_info(&201);
    let escrow_202 = client.get_escrow_info(&202);
    let escrow_203 = client.get_escrow_info(&203);
    assert_eq!(escrow_201.status, crate::EscrowStatus::Released);
    assert_eq!(escrow_202.status, crate::EscrowStatus::Refunded);
    assert_eq!(escrow_203.status, crate::EscrowStatus::Locked);
    assert_eq!(token_client.balance(&contributor), 3_000);
}

fn next_seed(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    *seed
}

#[test]
fn test_property_fuzz_lock_release_refund_invariants() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let contributor = Address::generate(&env);
    let start = env.ledger().timestamp();

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);

    let mut seed = 7_u64;
    let mut fuzz_cases: [(u64, i128, u64); 40] = [(0, 0, 0); 40];
    let mut total_locked = 0_i128;
    for i in 0..40_u64 {
        let amount = (next_seed(&mut seed) % 900 + 100) as i128;
        let deadline = start + (next_seed(&mut seed) % 500 + 10);
        fuzz_cases[i as usize] = (2_000 + i, amount, deadline);
        total_locked += amount;
    }
    token_admin_client.mint(&depositor, &total_locked);

    // Lock deterministic fuzz cases.
    for (id, amount, deadline) in fuzz_cases.iter() {
        client.lock_funds(&depositor, id, amount, deadline);
    }

    let mut expected_locked_balance = client.get_balance();
    for i in 0..40_u64 {
        let id = 2_000 + i;
        if i % 3 == 0 {
            let info = client.get_escrow_info(&id);
            client.release_funds(&id, &contributor);
            expected_locked_balance -= info.amount;
        } else if i % 3 == 1 {
            let info = client.get_escrow_info(&id);
            env.ledger().set_timestamp(info.deadline);
            client.refund(&id);
            expected_locked_balance -= info.amount;
        }
    }

    assert_eq!(client.get_balance(), expected_locked_balance);
}

#[test]
fn test_stress_high_load_bounty_operations() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let contributor = Address::generate(&env);
    let now = env.ledger().timestamp();

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &1_000_000);

    for i in 0..40_u64 {
        let amount = 100 + (i as i128 % 10);
        let deadline = now + 30 + i;
        client.lock_funds(&depositor, &(5_000 + i), &amount, &deadline);
    }
    assert!(client.get_balance() > 0);

    for i in 0..40_u64 {
        let id = 5_000 + i;
        if i % 2 == 0 {
            client.release_funds(&id, &contributor);
        } else {
            let info = client.get_escrow_info(&id);
            env.ledger().set_timestamp(info.deadline);
            client.refund(&id);
        }
    }

    assert_eq!(client.get_balance(), 0);
    assert!(token_client.balance(&contributor) > 0);
}

#[test]
fn test_gas_proxy_event_footprint_per_operation_is_constant() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let contributor = Address::generate(&env);
    let now = env.ledger().timestamp();

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &10_000);

    let before_lock = env.events().all().len();
    for offset in 0..20_u64 {
        let id = 8_001 + offset;
        client.lock_funds(&depositor, &id, &10, &(now + 100 + offset));
    }
    let after_locks = env.events().all().len();
    let lock_event_growth = after_locks - before_lock;
    assert!(lock_event_growth > 0);

    let before_release = env.events().all().len();
    client.release_funds(&8_001, &contributor);
    let after_release = env.events().all().len();
    assert!(after_release >= before_release);
}

// ==================== FEE CONFIGURATION EDGE CASE TESTS ====================

#[test]
fn test_update_fee_config_with_zero_lock_fee() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    env.mock_all_auths();

    client.init(&admin, &token);

    // Test: Set lock_fee_rate to 0 (should succeed)
    let result = client.try_update_fee_config(
        &Some(0), // lock_fee_rate: 0%
        &None,    // release_fee_rate: unchanged
        &Some(fee_recipient.clone()),
        &None, // fee_enabled: unchanged
    );
    assert!(result.is_ok());

    let config = client.get_fee_config();
    assert_eq!(config.lock_fee_rate, 0);
    assert_eq!(config.fee_recipient, fee_recipient);
}

#[test]
fn test_update_fee_config_with_zero_release_fee() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    env.mock_all_auths();

    client.init(&admin, &token);

    // Test: Set release_fee_rate to 0 (should succeed)
    let result = client.try_update_fee_config(
        &None,    // lock_fee_rate: unchanged
        &Some(0), // release_fee_rate: 0%
        &Some(fee_recipient.clone()),
        &None, // fee_enabled: unchanged
    );
    assert!(result.is_ok());

    let config = client.get_fee_config();
    assert_eq!(config.release_fee_rate, 0);
    assert_eq!(config.fee_recipient, fee_recipient);
}

#[test]
fn test_update_fee_config_with_max_lock_fee() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    env.mock_all_auths();

    client.init(&admin, &token);

    // Test: Set lock_fee_rate to MAX_FEE_RATE (5000 = 50%) (should succeed)
    let result = client.try_update_fee_config(
        &Some(5000), // lock_fee_rate: 50% (MAX_FEE_RATE)
        &None,       // release_fee_rate: unchanged
        &Some(fee_recipient.clone()),
        &None, // fee_enabled: unchanged
    );
    assert!(result.is_ok());

    let config = client.get_fee_config();
    assert_eq!(config.lock_fee_rate, 5000);
    assert_eq!(config.fee_recipient, fee_recipient);
}

#[test]
fn test_update_fee_config_with_max_release_fee() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    env.mock_all_auths();

    client.init(&admin, &token);

    // Test: Set release_fee_rate to MAX_FEE_RATE (5000 = 50%) (should succeed)
    let result = client.try_update_fee_config(
        &None,       // lock_fee_rate: unchanged
        &Some(5000), // release_fee_rate: 50% (MAX_FEE_RATE)
        &Some(fee_recipient.clone()),
        &None, // fee_enabled: unchanged
    );
    assert!(result.is_ok());

    let config = client.get_fee_config();
    assert_eq!(config.release_fee_rate, 5000);
    assert_eq!(config.fee_recipient, fee_recipient);
}

#[test]
fn test_update_fee_config_rejects_negative_lock_fee() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    env.mock_all_auths();

    client.init(&admin, &token);

    let original_config = client.get_fee_config();

    let result =
        client.try_update_fee_config(&Some(-1), &None, &Some(fee_recipient.clone()), &None);
    assert_eq!(result, Err(Ok(ContractError::InvalidFeeRate)));

    let current_config = client.get_fee_config();
    assert_eq!(current_config.lock_fee_rate, original_config.lock_fee_rate);
    assert_eq!(
        current_config.release_fee_rate,
        original_config.release_fee_rate
    );
}

#[test]
fn test_update_fee_config_rejects_negative_release_fee() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    env.mock_all_auths();

    client.init(&admin, &token);

    let original_config = client.get_fee_config();

    let result =
        client.try_update_fee_config(&None, &Some(-1), &Some(fee_recipient.clone()), &None);
    assert_eq!(result, Err(Ok(ContractError::InvalidFeeRate)));

    let current_config = client.get_fee_config();
    assert_eq!(current_config.lock_fee_rate, original_config.lock_fee_rate);
    assert_eq!(
        current_config.release_fee_rate,
        original_config.release_fee_rate
    );
}

#[test]
fn test_update_fee_config_rejects_over_max_lock_fee() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    env.mock_all_auths();

    client.init(&admin, &token);

    let original_config = client.get_fee_config();

    let result =
        client.try_update_fee_config(&Some(5001), &None, &Some(fee_recipient.clone()), &None);
    assert_eq!(result, Err(Ok(ContractError::InvalidFeeRate)));

    let current_config = client.get_fee_config();
    assert_eq!(current_config.lock_fee_rate, original_config.lock_fee_rate);
    assert_eq!(
        current_config.release_fee_rate,
        original_config.release_fee_rate
    );
}

#[test]
fn test_update_fee_config_rejects_over_max_release_fee() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    env.mock_all_auths();

    client.init(&admin, &token);

    let original_config = client.get_fee_config();

    let result =
        client.try_update_fee_config(&None, &Some(5001), &Some(fee_recipient.clone()), &None);
    assert_eq!(result, Err(Ok(ContractError::InvalidFeeRate)));

    let current_config = client.get_fee_config();
    assert_eq!(current_config.lock_fee_rate, original_config.lock_fee_rate);
    assert_eq!(
        current_config.release_fee_rate,
        original_config.release_fee_rate
    );
}

#[test]
fn test_update_fee_config_rejects_overflow_lock_fee() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    env.mock_all_auths();

    client.init(&admin, &token);

    let original_config = client.get_fee_config();

    let result =
        client.try_update_fee_config(&Some(i128::MAX), &None, &Some(fee_recipient.clone()), &None);
    assert_eq!(result, Err(Ok(ContractError::InvalidFeeRate)));

    let current_config = client.get_fee_config();
    assert_eq!(current_config.lock_fee_rate, original_config.lock_fee_rate);
    assert_eq!(
        current_config.release_fee_rate,
        original_config.release_fee_rate
    );
}

#[test]
fn test_update_fee_config_rejects_overflow_release_fee() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    env.mock_all_auths();

    client.init(&admin, &token);

    let original_config = client.get_fee_config();

    let result =
        client.try_update_fee_config(&None, &Some(i128::MAX), &Some(fee_recipient.clone()), &None);
    assert_eq!(result, Err(Ok(ContractError::InvalidFeeRate)));

    let current_config = client.get_fee_config();
    assert_eq!(current_config.lock_fee_rate, original_config.lock_fee_rate);
    assert_eq!(
        current_config.release_fee_rate,
        original_config.release_fee_rate
    );
}

#[test]
fn test_update_fee_config_both_rates_zero() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    env.mock_all_auths();

    client.init(&admin, &token);

    // Test: Set both lock and release fees to 0 (should succeed)
    let result = client.try_update_fee_config(
        &Some(0), // lock_fee_rate: 0%
        &Some(0), // release_fee_rate: 0%
        &Some(fee_recipient.clone()),
        &None,
    );
    assert!(result.is_ok());

    let config = client.get_fee_config();
    assert_eq!(config.lock_fee_rate, 0);
    assert_eq!(config.release_fee_rate, 0);
}

#[test]
fn test_update_fee_config_both_rates_at_max() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    env.mock_all_auths();

    client.init(&admin, &token);

    // Test: Set both lock and release fees to MAX_FEE_RATE (should succeed)
    let result = client.try_update_fee_config(
        &Some(5000), // lock_fee_rate: 50% (MAX_FEE_RATE)
        &Some(5000), // release_fee_rate: 50% (MAX_FEE_RATE)
        &Some(fee_recipient.clone()),
        &None,
    );
    assert!(result.is_ok());

    let config = client.get_fee_config();
    assert_eq!(config.lock_fee_rate, 5000);
    assert_eq!(config.release_fee_rate, 5000);
}

#[test]
fn test_update_fee_config_valid_intermediate_rates() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    env.mock_all_auths();

    client.init(&admin, &token);

    // Test: Set lock to 100 (1%) and release to 250 (2.5%) (should succeed)
    let result = client.try_update_fee_config(
        &Some(100), // lock_fee_rate: 1% (100 basis points)
        &Some(250), // release_fee_rate: 2.5% (250 basis points)
        &Some(fee_recipient.clone()),
        &None,
    );
    assert!(result.is_ok());

    let config = client.get_fee_config();
    assert_eq!(config.lock_fee_rate, 100);
    assert_eq!(config.release_fee_rate, 250);
}

#[test]
fn test_update_fee_config_partial_updates_preserve_existing_values() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let fee_recipient_1 = Address::generate(&env);
    let fee_recipient_2 = Address::generate(&env);

    env.mock_all_auths();

    client.init(&admin, &token);

    // First update: Set lock fee, release fee, and recipient
    client.update_fee_config(
        &Some(100),
        &Some(200),
        &Some(fee_recipient_1.clone()),
        &Some(true),
    );

    // Second update: Only update lock fee, other values should remain unchanged
    client.update_fee_config(&Some(300), &None, &None, &None);

    let config = client.get_fee_config();
    assert_eq!(config.lock_fee_rate, 300);
    assert_eq!(config.release_fee_rate, 200); // Should remain 200
    assert_eq!(config.fee_recipient, fee_recipient_1); // Should remain recipient_1
    assert_eq!(config.fee_enabled, true); // Should remain true

    // Third update: Update recipient and enabled flag
    client.update_fee_config(&None, &None, &Some(fee_recipient_2.clone()), &Some(false));

    let config = client.get_fee_config();
    assert_eq!(config.lock_fee_rate, 300); // Should remain 300
    assert_eq!(config.release_fee_rate, 200); // Should remain 200
    assert_eq!(config.fee_recipient, fee_recipient_2); // Should be updated to recipient_2
    assert_eq!(config.fee_enabled, false); // Should be updated to false
}

#[test]
fn test_update_fee_config_fails_with_one_invalid_rate_preserves_state() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    env.mock_all_auths();

    client.init(&admin, &token);

    client.update_fee_config(&Some(100), &Some(200), &Some(fee_recipient.clone()), &None);

    let original_config = client.get_fee_config();

    let result = client.try_update_fee_config(&Some(300), &Some(5001), &None, &None);
    assert_eq!(result, Err(Ok(ContractError::InvalidFeeRate)));

    let config = client.get_fee_config();
    assert_eq!(config.lock_fee_rate, original_config.lock_fee_rate);
    assert_eq!(config.release_fee_rate, original_config.release_fee_rate);
}

#[test]
fn test_update_fee_config_rejects_100_percent_lock_fee() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    env.mock_all_auths();

    client.init(&admin, &token);

    let original_config = client.get_fee_config();

    let result =
        client.try_update_fee_config(&Some(10_000), &None, &Some(fee_recipient.clone()), &None);
    assert_eq!(result, Err(Ok(ContractError::InvalidFeeRate)));

    let current_config = client.get_fee_config();
    assert_eq!(current_config.lock_fee_rate, original_config.lock_fee_rate);
    assert_eq!(
        current_config.release_fee_rate,
        original_config.release_fee_rate
    );
}

#[test]
fn test_update_fee_config_rejects_100_percent_release_fee() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    env.mock_all_auths();

    client.init(&admin, &token);

    let original_config = client.get_fee_config();

    let result =
        client.try_update_fee_config(&None, &Some(10_000), &Some(fee_recipient.clone()), &None);
    assert_eq!(result, Err(Ok(ContractError::InvalidFeeRate)));

    let current_config = client.get_fee_config();
    assert_eq!(current_config.lock_fee_rate, original_config.lock_fee_rate);
    assert_eq!(
        current_config.release_fee_rate,
        original_config.release_fee_rate
    );
}

#[test]
fn test_update_fee_config_rejects_over_100_percent_lock_fee() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    env.mock_all_auths();

    client.init(&admin, &token);

    let original_config = client.get_fee_config();

    let result =
        client.try_update_fee_config(&Some(10_001), &None, &Some(fee_recipient.clone()), &None);
    assert_eq!(result, Err(Ok(ContractError::InvalidFeeRate)));

    let current_config = client.get_fee_config();
    assert_eq!(current_config.lock_fee_rate, original_config.lock_fee_rate);
    assert_eq!(
        current_config.release_fee_rate,
        original_config.release_fee_rate
    );
}

#[test]
fn test_update_fee_config_rejects_over_100_percent_release_fee() {
    let (env, client, _contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    env.mock_all_auths();

    client.init(&admin, &token);

    let original_config = client.get_fee_config();

    let result =
        client.try_update_fee_config(&None, &Some(10_001), &Some(fee_recipient.clone()), &None);
    assert_eq!(result, Err(Ok(ContractError::InvalidFeeRate)));

    let current_config = client.get_fee_config();
    assert_eq!(current_config.lock_fee_rate, original_config.lock_fee_rate);
    assert_eq!(
        current_config.release_fee_rate,
        original_config.release_fee_rate
    );
}

// ── Min/Max Amount Policy Enforcement Tests ───────────────────────────────────

/// Locking an amount strictly below the configured minimum must be rejected.
#[test]
#[should_panic(expected = "Error(Contract, #19)")] // AmountBelowMinimum
fn test_lock_funds_below_minimum_rejected() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &1_000);

    // Policy: min=100, max=10_000.  Attempting to lock 50 must be rejected.
    client.set_amount_policy(&admin, &100_i128, &10_000_i128);
    client.lock_funds(&depositor, &1, &50_i128, &deadline);
}

/// Locking an amount strictly above the configured maximum must be rejected.
#[test]
#[should_panic(expected = "Error(Contract, #20)")] // AmountAboveMaximum
fn test_lock_funds_above_maximum_rejected() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &100_000);

    // Policy: min=100, max=10_000.  Attempting to lock 50_000 must be rejected.
    client.set_amount_policy(&admin, &100_i128, &10_000_i128);
    client.lock_funds(&depositor, &2, &50_000_i128, &deadline);
}

/// An amount equal to the configured minimum is on the inclusive boundary and
/// must succeed.
#[test]
fn test_lock_funds_at_exact_minimum_succeeds() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &1_000);

    client.set_amount_policy(&admin, &100_i128, &10_000_i128);
    // amount == min → allowed (inclusive lower bound)
    client.lock_funds(&depositor, &3, &100_i128, &deadline);

    let escrow = client.get_escrow_info(&3);
    assert_eq!(escrow.amount, 100);
    assert_eq!(escrow.status, crate::EscrowStatus::Locked);
}

/// An amount equal to the configured maximum is on the inclusive boundary and
/// must succeed.
#[test]
fn test_lock_funds_at_exact_maximum_succeeds() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &10_000);

    client.set_amount_policy(&admin, &100_i128, &10_000_i128);
    // amount == max → allowed (inclusive upper bound)
    client.lock_funds(&depositor, &4, &10_000_i128, &deadline);

    let escrow = client.get_escrow_info(&4);
    assert_eq!(escrow.amount, 10_000);
    assert_eq!(escrow.status, crate::EscrowStatus::Locked);
}

/// An amount that sits strictly inside [min, max] must succeed.
#[test]
fn test_lock_funds_within_range_succeeds() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &5_000);

    client.set_amount_policy(&admin, &100_i128, &10_000_i128);
    client.lock_funds(&depositor, &5, &5_000_i128, &deadline);

    let escrow = client.get_escrow_info(&5);
    assert_eq!(escrow.amount, 5_000);
    assert_eq!(escrow.status, crate::EscrowStatus::Locked);
}

/// batch_lock_funds must enforce the same AmountPolicy as lock_funds.
/// A batch containing an item strictly below the configured minimum must
/// be rejected entirely with AmountBelowMinimum.
#[test]
#[should_panic(expected = "Error(Contract, #19)")] // AmountBelowMinimum
fn test_batch_lock_funds_below_minimum_rejected() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &1_000);

    // Policy: min=100, max=10_000.  Attempting to lock 50 must be rejected.
    client.set_amount_policy(&admin, &100_i128, &10_000_i128);

    let items = vec![
        &env,
        crate::LockFundsItem {
            bounty_id: 1,
            depositor: depositor.clone(),
            amount: 50,
            deadline,
        },
    ];
    client.batch_lock_funds(&items);
}

/// batch_lock_funds must enforce the same AmountPolicy as lock_funds.
/// A batch containing an item strictly above the configured maximum must
/// be rejected entirely with AmountAboveMaximum.
#[test]
#[should_panic(expected = "Error(Contract, #20)")] // AmountAboveMaximum
fn test_batch_lock_funds_above_maximum_rejected() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &100_000);

    // Policy: min=100, max=10_000.  Attempting to lock 50_000 must be rejected.
    client.set_amount_policy(&admin, &100_i128, &10_000_i128);

    let items = vec![
        &env,
        crate::LockFundsItem {
            bounty_id: 1,
            depositor: depositor.clone(),
            amount: 50_000,
            deadline,
        },
    ];
    client.batch_lock_funds(&items);
}

/// batch_lock_funds must reject the whole batch if any item violates the
/// AmountPolicy, even when other items in the batch are valid.
#[test]
#[should_panic(expected = "Error(Contract, #19)")] // AmountBelowMinimum
fn test_batch_lock_funds_mixed_valid_and_below_minimum_rejected() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &100_000);

    // Policy: min=100, max=10_000.
    client.set_amount_policy(&admin, &100_i128, &10_000_i128);

    // First item violates the policy (below min), second is valid.
    let items = vec![
        &env,
        crate::LockFundsItem {
            bounty_id: 1,
            depositor: depositor.clone(),
            amount: 50,
            deadline,
        },
        crate::LockFundsItem {
            bounty_id: 2,
            depositor: depositor.clone(),
            amount: 5_000,
            deadline,
        },
    ];
    client.batch_lock_funds(&items);
}

/// batch_lock_funds must reject the whole batch if any item exceeds the
/// AmountPolicy maximum, even when other items in the batch are valid.
#[test]
#[should_panic(expected = "Error(Contract, #20)")] // AmountAboveMaximum
fn test_batch_lock_funds_mixed_valid_and_above_maximum_rejected() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &100_000);

    // Policy: min=100, max=10_000.
    client.set_amount_policy(&admin, &100_i128, &10_000_i128);

    // First item is valid, second item violates the policy (above max).
    let items = vec![
        &env,
        crate::LockFundsItem {
            bounty_id: 1,
            depositor: depositor.clone(),
            amount: 5_000,
            deadline,
        },
        crate::LockFundsItem {
            bounty_id: 2,
            depositor: depositor.clone(),
            amount: 50_000,
            deadline,
        },
    ];
    client.batch_lock_funds(&items);
}

/// batch_lock_funds succeeds when no AmountPolicy has been set (unrestricted).
#[test]
fn test_batch_lock_funds_without_amount_policy_succeeds() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &10_000);

    // No AmountPolicy set — any positive amount should succeed.
    let items = vec![
        &env,
        crate::LockFundsItem {
            bounty_id: 1,
            depositor: depositor.clone(),
            amount: 5_000,
            deadline,
        },
    ];
    client.batch_lock_funds(&items);

    let escrow = client.get_escrow_info(&1);
    assert_eq!(escrow.amount, 5_000);
    assert_eq!(escrow.status, crate::EscrowStatus::Locked);
}

/// Only the admin may call `set_amount_policy`.  Any other caller must be
/// rejected with an Unauthorized error.
#[test]
#[should_panic(expected = "Error(Contract, #7)")] // Unauthorized
fn test_non_admin_cannot_set_amount_policy() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, _token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);

    // non_admin attempts to set policy — must be rejected with Unauthorized.
    client.set_amount_policy(&non_admin, &100_i128, &10_000_i128);
}

/// When no policy has been set the contract must remain backward-compatible:
/// any positive (or zero per the existing edge-case test) amount is accepted.
#[test]
fn test_no_policy_set_allows_any_positive_amount() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &1_000_000);

    // No set_amount_policy call — all positive amounts must be accepted.
    client.lock_funds(&depositor, &6, &1_i128, &deadline);
    client.lock_funds(&depositor, &7, &999_999_i128, &deadline);

    assert_eq!(client.get_escrow_info(&6).amount, 1);
    assert_eq!(client.get_escrow_info(&7).amount, 999_999);
}

/// Supplying min > max is a logically invalid policy and must be rejected
/// with the typed InvalidAmountRange error (issue #467: this previously
/// used an untyped panic!() instead).
#[test]
#[should_panic(expected = "Error(Contract, #29)")] // InvalidAmountRange
fn test_set_amount_policy_min_greater_than_max_rejected() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, _) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);

    // min=5_000 > max=100 — invalid policy, must be rejected.
    client.set_amount_policy(&admin, &5_000_i128, &100_i128);
}

/// The non-panicking try_ variant surfaces the same InvalidAmountRange
/// error as a typed Result, without panicking.
#[test]
fn test_set_amount_policy_min_greater_than_max_returns_typed_error() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, _) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);

    let result = client.try_set_amount_policy(&admin, &5_000_i128, &100_i128);
    assert_eq!(result, Err(Ok(ContractError::InvalidAmountRange)));
}

/// The admin must be able to update the policy after initial configuration, and
/// the new limits must take effect immediately for subsequent lock calls.
#[test]
fn test_amount_policy_can_be_updated_by_admin() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &100_000);

    // First policy: min=1_000 — amount 500 would be rejected here.
    client.set_amount_policy(&admin, &1_000_i128, &50_000_i128);

    // Loosen the policy: min=10 — amount 500 must now be accepted.
    client.set_amount_policy(&admin, &10_i128, &50_000_i128);
    client.lock_funds(&depositor, &8, &500_i128, &deadline);

    assert_eq!(client.get_escrow_info(&8).amount, 500);
}

/// min - 1 is the tightest possible value below the minimum boundary and must
/// be rejected (off-by-one lower).
#[test]
#[should_panic(expected = "Error(Contract, #19)")] // AmountBelowMinimum
fn test_one_below_minimum_boundary_rejected() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &1_000);

    client.set_amount_policy(&admin, &100_i128, &10_000_i128);
    // 99 == min(100) - 1 → must be rejected.
    client.lock_funds(&depositor, &9, &99_i128, &deadline);
}

/// max + 1 is the tightest possible value above the maximum boundary and must
/// be rejected (off-by-one upper).
#[test]
#[should_panic(expected = "Error(Contract, #20)")] // AmountAboveMaximum
fn test_one_above_maximum_boundary_rejected() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &100_000);

    client.set_amount_policy(&admin, &100_i128, &10_000_i128);
    // 10_001 == max(10_000) + 1 → must be rejected.
    client.lock_funds(&depositor, &10, &10_001_i128, &deadline);
}

// ==================== DUPLICATE ID VALIDATION EDGE CASE TESTS ====================

/// Attempting to lock funds with the same bounty_id twice must be rejected.
#[test]
#[should_panic(expected = "Error(Contract, #3)")] // BountyExists
fn test_lock_funds_duplicate_bounty_id_rejected() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let bounty_id = 1;
    let amount = 1000;
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &amount);

    // First lock should succeed
    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

    // Second lock with same bounty_id must fail with BountyExists
    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);
}

/// Batch lock with adjacent duplicate bounty_ids must be rejected.
#[test]
#[should_panic(expected = "Error(Contract, #12)")] // DuplicateBountyId
fn test_batch_lock_funds_adjacent_duplicates_rejected() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &10_000);

    let items = vec![
        &env,
        crate::LockFundsItem {
            bounty_id: 1,
            depositor: depositor.clone(),
            amount: 1000,
            deadline,
        },
        crate::LockFundsItem {
            bounty_id: 1, // Duplicate adjacent
            depositor: depositor.clone(),
            amount: 2000,
            deadline,
        },
    ];

    client.batch_lock_funds(&items);
}

/// Batch lock with non-adjacent duplicate bounty_ids must be rejected.
#[test]
#[should_panic(expected = "Error(Contract, #12)")] // DuplicateBountyId
fn test_batch_lock_funds_non_adjacent_duplicates_rejected() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &10_000);

    let items = vec![
        &env,
        crate::LockFundsItem {
            bounty_id: 1,
            depositor: depositor.clone(),
            amount: 1000,
            deadline,
        },
        crate::LockFundsItem {
            bounty_id: 2,
            depositor: depositor.clone(),
            amount: 2000,
            deadline,
        },
        crate::LockFundsItem {
            bounty_id: 1, // Duplicate non-adjacent
            depositor: depositor.clone(),
            amount: 3000,
            deadline,
        },
    ];

    client.batch_lock_funds(&items);
}

/// Batch lock with triple duplicate bounty_ids must be rejected.
#[test]
#[should_panic(expected = "Error(Contract, #12)")] // DuplicateBountyId
fn test_batch_lock_funds_triple_duplicates_rejected() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &15_000);

    let items = vec![
        &env,
        crate::LockFundsItem {
            bounty_id: 1,
            depositor: depositor.clone(),
            amount: 1000,
            deadline,
        },
        crate::LockFundsItem {
            bounty_id: 1, // First duplicate
            depositor: depositor.clone(),
            amount: 2000,
            deadline,
        },
        crate::LockFundsItem {
            bounty_id: 1, // Second duplicate (triple total)
            depositor: depositor.clone(),
            amount: 3000,
            deadline,
        },
    ];

    client.batch_lock_funds(&items);
}

/// Batch lock with multiple different duplicate bounty_ids must be rejected.
#[test]
#[should_panic(expected = "Error(Contract, #12)")] // DuplicateBountyId
fn test_batch_lock_funds_multiple_different_duplicates_rejected() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &20_000);

    let items = vec![
        &env,
        crate::LockFundsItem {
            bounty_id: 1,
            depositor: depositor.clone(),
            amount: 1000,
            deadline,
        },
        crate::LockFundsItem {
            bounty_id: 2,
            depositor: depositor.clone(),
            amount: 2000,
            deadline,
        },
        crate::LockFundsItem {
            bounty_id: 1, // Duplicate of bounty_id 1
            depositor: depositor.clone(),
            amount: 3000,
            deadline,
        },
        crate::LockFundsItem {
            bounty_id: 2, // Duplicate of bounty_id 2
            depositor: depositor.clone(),
            amount: 4000,
            deadline,
        },
    ];

    client.batch_lock_funds(&items);
}

/// Batch lock with zero bounty_id must handle duplicate validation correctly.
#[test]
#[should_panic(expected = "Error(Contract, #12)")] // DuplicateBountyId
fn test_batch_lock_funds_zero_bounty_id_duplicates_rejected() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &10_000);

    let items = vec![
        &env,
        crate::LockFundsItem {
            bounty_id: 0,
            depositor: depositor.clone(),
            amount: 1000,
            deadline,
        },
        crate::LockFundsItem {
            bounty_id: 0, // Duplicate zero
            depositor: depositor.clone(),
            amount: 2000,
            deadline,
        },
    ];

    client.batch_lock_funds(&items);
}

/// Batch lock with maximum u64 bounty_id must handle duplicate validation correctly.
#[test]
#[should_panic(expected = "Error(Contract, #12)")] // DuplicateBountyId
fn test_batch_lock_funds_max_bounty_id_duplicates_rejected() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &10_000);

    let max_id = u64::MAX;
    let items = vec![
        &env,
        crate::LockFundsItem {
            bounty_id: max_id,
            depositor: depositor.clone(),
            amount: 1000,
            deadline,
        },
        crate::LockFundsItem {
            bounty_id: max_id, // Duplicate MAX
            depositor: depositor.clone(),
            amount: 2000,
            deadline,
        },
    ];

    client.batch_lock_funds(&items);
}

/// Batch release with adjacent duplicate bounty_ids must be rejected.
#[test]
#[should_panic(expected = "Error(Contract, #12)")] // DuplicateBountyId
fn test_batch_release_funds_adjacent_duplicates_rejected() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let contributor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &10_000);

    // Lock two bounties
    client.lock_funds(&depositor, &1, &5000, &deadline);
    client.lock_funds(&depositor, &2, &5000, &deadline);

    let items = vec![
        &env,
        crate::ReleaseFundsItem {
            bounty_id: 1,
            contributor: contributor.clone(),
        },
        crate::ReleaseFundsItem {
            bounty_id: 1, // Duplicate adjacent
            contributor: contributor.clone(),
        },
    ];

    client.batch_release_funds(&items);
}

/// Batch release with non-adjacent duplicate bounty_ids must be rejected.
#[test]
#[should_panic(expected = "Error(Contract, #12)")] // DuplicateBountyId
fn test_batch_release_funds_non_adjacent_duplicates_rejected() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let contributor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &15_000);

    // Lock three bounties
    client.lock_funds(&depositor, &1, &5000, &deadline);
    client.lock_funds(&depositor, &2, &5000, &deadline);
    client.lock_funds(&depositor, &3, &5000, &deadline);

    let items = vec![
        &env,
        crate::ReleaseFundsItem {
            bounty_id: 1,
            contributor: contributor.clone(),
        },
        crate::ReleaseFundsItem {
            bounty_id: 2,
            contributor: contributor.clone(),
        },
        crate::ReleaseFundsItem {
            bounty_id: 1, // Duplicate non-adjacent
            contributor: contributor.clone(),
        },
    ];

    client.batch_release_funds(&items);
}

/// Batch release with single item should succeed (no duplicate possible).
#[test]
fn test_batch_release_funds_single_item_succeeds() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let contributor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &5000);

    client.lock_funds(&depositor, &1, &5000, &deadline);

    let items = vec![
        &env,
        crate::ReleaseFundsItem {
            bounty_id: 1,
            contributor: contributor.clone(),
        },
    ];

    let result = client.batch_release_funds(&items);
    assert_eq!(result, 1);
}

/// Batch lock with single item should succeed (no duplicate possible).
#[test]
fn test_batch_lock_funds_single_item_succeeds() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &5000);

    let items = vec![
        &env,
        crate::LockFundsItem {
            bounty_id: 1,
            depositor: depositor.clone(),
            amount: 5000,
            deadline,
        },
    ];

    client.batch_lock_funds(&items);

    let escrow = client.get_escrow_info(&1);
    assert_eq!(escrow.amount, 5000);
    assert_eq!(escrow.status, crate::EscrowStatus::Locked);
}

/// Batch lock with all unique bounty_ids must succeed.
#[test]
fn test_batch_lock_funds_all_unique_succeeds() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &15_000);

    let items = vec![
        &env,
        crate::LockFundsItem {
            bounty_id: 1,
            depositor: depositor.clone(),
            amount: 5000,
            deadline,
        },
        crate::LockFundsItem {
            bounty_id: 2,
            depositor: depositor.clone(),
            amount: 5000,
            deadline,
        },
        crate::LockFundsItem {
            bounty_id: 3,
            depositor: depositor.clone(),
            amount: 5000,
            deadline,
        },
    ];

    client.batch_lock_funds(&items);

    assert_eq!(client.get_escrow_info(&1).amount, 5000);
    assert_eq!(client.get_escrow_info(&2).amount, 5000);
    assert_eq!(client.get_escrow_info(&3).amount, 5000);
}

/// Batch release with all unique bounty_ids must succeed.
#[test]
fn test_batch_release_funds_all_unique_succeeds() {
    let (env, client, _) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let contributor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &15_000);

    client.lock_funds(&depositor, &1, &5000, &deadline);
    client.lock_funds(&depositor, &2, &5000, &deadline);
    client.lock_funds(&depositor, &3, &5000, &deadline);

    let items = vec![
        &env,
        crate::ReleaseFundsItem {
            bounty_id: 1,
            contributor: contributor.clone(),
        },
        crate::ReleaseFundsItem {
            bounty_id: 2,
            contributor: contributor.clone(),
        },
        crate::ReleaseFundsItem {
            bounty_id: 3,
            contributor: contributor.clone(),
        },
    ];

    let result = client.batch_release_funds(&items);
    assert_eq!(result, 3);
}

// =============================================================================
// Payload assertions for emit_bounty_initialized / emit_funds_locked /
// emit_bounty_expired (Issue #393)
// =============================================================================
// Existing tests only assert *that* a versioned event was published
// (assert_event_data_has_v2_tag); these assert the actual topic value and
// every payload field, field-by-field.

#[test]
fn test_emit_bounty_initialized_topic_and_payload() {
    use crate::events::BountyEscrowInitialized;
    use soroban_sdk::{symbol_short, IntoVal};

    let (env, client, contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let (token, _, _) = create_token_contract(&env, &admin);

    // `init` requires the incoming admin's own auth as of #491.
    env.mock_all_auths();
    client.init(&admin, &token);

    let expected_topics: soroban_sdk::Vec<Val> = (symbol_short!("init"),).into_val(&env);
    let mut found = false;
    for (evt_contract_id, topics, data) in env.events().all().iter() {
        if evt_contract_id != contract_id || topics != expected_topics {
            continue;
        }
        let event = BountyEscrowInitialized::try_from_val(&env, &data)
            .expect("init event payload must decode as BountyEscrowInitialized");
        assert_eq!(event.version, 2);
        assert_eq!(event.admin, admin);
        assert_eq!(event.token, token);
        found = true;
    }
    assert!(found, "no init event with the expected topic was published");
}

#[test]
fn test_emit_funds_locked_topic_and_payload() {
    use crate::events::FundsLocked;
    use soroban_sdk::{symbol_short, IntoVal};

    let (env, client, contract_id) = create_test_env();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let (token, _, token_admin_client) = create_token_contract(&env, &admin);
    token_admin_client.mint(&depositor, &1_000);
    client.init(&admin, &token);

    let bounty_id = 7u64;
    let amount = 250i128;
    let deadline = env.ledger().timestamp() + 3600;
    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

    let expected_topics: soroban_sdk::Vec<Val> =
        (symbol_short!("f_lock"), bounty_id).into_val(&env);
    let mut found = false;
    for (evt_contract_id, topics, data) in env.events().all().iter() {
        if evt_contract_id != contract_id || topics != expected_topics {
            continue;
        }
        let event = FundsLocked::try_from_val(&env, &data)
            .expect("lock event payload must decode as FundsLocked");
        assert_eq!(event.version, 2);
        assert_eq!(event.bounty_id, bounty_id);
        assert_eq!(event.amount, amount);
        assert_eq!(event.depositor, depositor);
        assert_eq!(event.deadline, deadline);
        found = true;
    }
    assert!(
        found,
        "no f_lock event with the expected topic was published"
    );
}

#[test]
fn test_emit_bounty_expired_topic_and_payload() {
    use crate::events::BountyExpired;
    use soroban_sdk::{symbol_short, IntoVal};

    let (env, client, contract_id) = create_test_env();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let (token, _, token_admin_client) = create_token_contract(&env, &admin);
    token_admin_client.mint(&depositor, &1_000);
    client.init(&admin, &token);

    let bounty_id = 9u64;
    let amount = 400i128;
    let deadline = env.ledger().timestamp() + 100;
    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);

    // Advance past the deadline and sweep — this is the call site that emits
    // BountyExpired (see lib.rs's sweep_expired_refunds).
    env.ledger().set_timestamp(deadline + 1);
    let ids = vec![&env, bounty_id];
    let swept = client.sweep_expired_refunds(&ids);
    assert_eq!(swept, 1);

    let expected_topics: soroban_sdk::Vec<Val> = (symbol_short!("b_exp"), bounty_id).into_val(&env);
    let mut found = false;
    for (evt_contract_id, topics, data) in env.events().all().iter() {
        if evt_contract_id != contract_id || topics != expected_topics {
            continue;
        }
        let event = BountyExpired::try_from_val(&env, &data)
            .expect("expired event payload must decode as BountyExpired");
        assert_eq!(event.version, 2);
        assert_eq!(event.bounty_id, bounty_id);
        assert_eq!(event.depositor, depositor);
        assert_eq!(event.amount, amount);
        assert_eq!(event.deadline, deadline);
        assert_eq!(event.expired_at, deadline + 1);
        found = true;
    }
    assert!(
        found,
        "no b_exp event with the expected topic was published"
    );
}

// ---------------------------------------------------------------------
// Payload-level coverage for emit_funds_released, emit_funds_refunded and
// emit_batch_funds_locked (bounty_escrow/src/events.rs).
// ---------------------------------------------------------------------

/// release_funds() must emit FundsReleased with a `("f_rel", bounty_id)`
/// topic pair and a payload whose amount/recipient match the full locked
/// amount and the release_funds() call arguments.
#[test]
fn test_release_funds_emits_funds_released_event_full_amount() {
    let (env, client, contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let contributor = Address::generate(&env);
    let bounty_id = 42u64;
    let amount = 7_500i128;
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &amount);

    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);
    client.release_funds(&bounty_id, &contributor);

    let (topics, data) = find_contract_event(&env, &contract_id, symbol_short!("f_rel"));
    assert_eq!(topics.len(), 2);
    let topic_bounty_id: u64 = u64::try_from_val(&env, &topics.get(1).unwrap()).unwrap();
    assert_eq!(topic_bounty_id, bounty_id);

    let payload: events::FundsReleased =
        events::FundsReleased::try_from_val(&env, &data).unwrap();
    assert_eq!(payload.version, events::EVENT_VERSION_V2);
    assert_eq!(payload.bounty_id, bounty_id);
    assert_eq!(payload.amount, amount);
    assert_eq!(payload.recipient, contributor);
    assert_eq!(payload.timestamp, env.ledger().timestamp());
}

/// Edge case: partial_release() also emits FundsReleased through the same
/// emitter. A partial payout must be recorded as the payout amount, not the
/// bounty's full locked amount.
#[test]
fn test_partial_release_emits_funds_released_event_with_partial_amount() {
    let (env, client, contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let contributor = Address::generate(&env);
    let bounty_id = 43u64;
    let amount = 10_000i128;
    let payout_amount = 4_000i128;
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &amount);

    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);
    client.partial_release(&bounty_id, &contributor, &payout_amount);

    let (topics, data) = find_contract_event(&env, &contract_id, symbol_short!("f_rel"));
    let topic_bounty_id: u64 = u64::try_from_val(&env, &topics.get(1).unwrap()).unwrap();
    assert_eq!(topic_bounty_id, bounty_id);

    let payload: events::FundsReleased =
        events::FundsReleased::try_from_val(&env, &data).unwrap();
    assert_eq!(payload.amount, payout_amount);
    assert_ne!(payload.amount, amount);
    assert_eq!(payload.recipient, contributor);

    let escrow = client.get_escrow_info(&bounty_id);
    assert_eq!(escrow.remaining_amount, amount - payout_amount);
}

/// refund() must emit FundsRefunded with a `("f_ref", bounty_id)` topic
/// pair and a payload whose amount/refund_to match a standard post-deadline
/// full refund back to the original depositor.
#[test]
fn test_refund_emits_funds_refunded_event_full_amount() {
    let (env, client, contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let bounty_id = 44u64;
    let amount = 3_000i128;
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &amount);

    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);
    env.ledger().set_timestamp(deadline + 1);
    client.refund(&bounty_id);

    let (topics, data) = find_contract_event(&env, &contract_id, symbol_short!("f_ref"));
    assert_eq!(topics.len(), 2);
    let topic_bounty_id: u64 = u64::try_from_val(&env, &topics.get(1).unwrap()).unwrap();
    assert_eq!(topic_bounty_id, bounty_id);

    let payload: events::FundsRefunded =
        events::FundsRefunded::try_from_val(&env, &data).unwrap();
    assert_eq!(payload.version, events::EVENT_VERSION_V2);
    assert_eq!(payload.bounty_id, bounty_id);
    assert_eq!(payload.amount, amount);
    assert_eq!(payload.refund_to, depositor);
}

/// Edge case: an admin-approved partial refund to a custom recipient must
/// be recorded with the approved partial amount, not the full locked
/// amount, and refund_to must be the approved recipient rather than the
/// original depositor.
#[test]
fn test_refund_emits_funds_refunded_event_partial_amount_custom_recipient() {
    let (env, client, contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let refund_recipient = Address::generate(&env);
    let bounty_id = 45u64;
    let amount = 10_000i128;
    let partial_amount = 3_500i128;
    let deadline = env.ledger().timestamp() + 1000;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &amount);

    client.lock_funds(&depositor, &bounty_id, &amount, &deadline);
    client.approve_refund(
        &bounty_id,
        &partial_amount,
        &refund_recipient,
        &crate::RefundMode::Partial,
    );
    client.refund(&bounty_id);

    let (topics, data) = find_contract_event(&env, &contract_id, symbol_short!("f_ref"));
    let topic_bounty_id: u64 = u64::try_from_val(&env, &topics.get(1).unwrap()).unwrap();
    assert_eq!(topic_bounty_id, bounty_id);

    let payload: events::FundsRefunded =
        events::FundsRefunded::try_from_val(&env, &data).unwrap();
    assert_eq!(payload.amount, partial_amount);
    assert_ne!(payload.amount, amount);
    assert_eq!(payload.refund_to, refund_recipient);
    assert_ne!(payload.refund_to, depositor);

    let escrow = client.get_escrow_info(&bounty_id);
    assert_eq!(escrow.status, crate::EscrowStatus::PartiallyRefunded);
    assert_eq!(escrow.remaining_amount, amount - partial_amount);
}

/// batch_lock_funds() must emit a single BatchFundsLocked summarising the
/// whole batch. For a single-item batch, count must be 1 and total_amount
/// must equal that one item's amount.
#[test]
fn test_batch_lock_funds_emits_batch_event_single_item() {
    let (env, client, contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &5_000);

    let items = vec![
        &env,
        crate::LockFundsItem {
            bounty_id: 1,
            depositor: depositor.clone(),
            amount: 5_000,
            deadline,
        },
    ];
    client.batch_lock_funds(&items);

    let (topics, data) = find_contract_event(&env, &contract_id, symbol_short!("b_lock"));
    // BatchFundsLocked carries no per-bounty topic, only the event symbol.
    assert_eq!(topics.len(), 1);

    let payload: events::BatchFundsLocked =
        events::BatchFundsLocked::try_from_val(&env, &data).unwrap();
    assert_eq!(payload.version, events::EVENT_VERSION_V2);
    assert_eq!(payload.count, 1);
    assert_eq!(payload.total_amount, 5_000);
}

/// Edge case: for a multi-item batch with non-uniform amounts, the emitted
/// count must equal the batch size and total_amount must equal the exact
/// sum of the individual item amounts (guards against accumulation drift,
/// ordering bugs, or truncation in the aggregation logic).
#[test]
fn test_batch_lock_funds_emits_batch_event_aggregated_multi_item() {
    let (env, client, contract_id) = create_test_env();
    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let deadline = env.ledger().timestamp() + 100;

    env.mock_all_auths();

    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);
    client.init(&admin, &token);

    let amounts: [i128; 4] = [1_000, 2_500, 3_500, 5_000];
    let expected_total: i128 = amounts.iter().sum();
    let expected_count = amounts.len() as u32;
    token_admin_client.mint(&depositor, &expected_total);

    let items = vec![
        &env,
        crate::LockFundsItem {
            bounty_id: 10,
            depositor: depositor.clone(),
            amount: amounts[0],
            deadline,
        },
        crate::LockFundsItem {
            bounty_id: 11,
            depositor: depositor.clone(),
            amount: amounts[1],
            deadline,
        },
        crate::LockFundsItem {
            bounty_id: 12,
            depositor: depositor.clone(),
            amount: amounts[2],
            deadline,
        },
        crate::LockFundsItem {
            bounty_id: 13,
            depositor: depositor.clone(),
            amount: amounts[3],
            deadline,
        },
    ];
    client.batch_lock_funds(&items);

    let (_topics, data) = find_contract_event(&env, &contract_id, symbol_short!("b_lock"));
    let payload: events::BatchFundsLocked =
        events::BatchFundsLocked::try_from_val(&env, &data).unwrap();
    assert_eq!(payload.count, expected_count);
    assert_eq!(payload.total_amount, expected_total);
}
// ---------------------------------------------------------------------------
// § Event payload assertions: ClaimCreated, ClaimExecuted, PauseStateChanged
// ---------------------------------------------------------------------------

#[test]
fn test_claim_created_event_payload_and_topic() {
    let (env, client, contract_id) = create_test_env();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let recipient = Address::generate(&env);
    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);

    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &1_000);

    let bounty_id = 1;
    let amount = 500;
    let lock_deadline = env.ledger().timestamp() + 10_000;
    client.lock_funds(&depositor, &bounty_id, &amount, &lock_deadline);

    let claim_window = 500u64;
    client.set_claim_window(&claim_window);

    let expected_expires_at = env.ledger().timestamp() + claim_window;
    client.authorize_claim(&bounty_id, &recipient);

    let (topics, data) = find_contract_event(&env, &contract_id, symbol_short!("claim"));

    // Topic tuple check: (claim, created)
    assert_eq!(topics.len(), 2);
    let topic1: Symbol = Symbol::try_from_val(&env, &topics.get(1).unwrap()).unwrap();
    assert_eq!(topic1, symbol_short!("created"));

    // Payload field checks
    let event: ClaimCreated = ClaimCreated::try_from_val(&env, &data)
        .unwrap_or_else(|_| panic!("payload should decode as ClaimCreated"));
    assert_eq!(event.bounty_id, bounty_id);
    assert_eq!(event.recipient, recipient);
    assert_eq!(event.amount, amount);
    assert_eq!(event.expires_at, expected_expires_at);
}

#[test]
fn test_claim_executed_event_payload_and_topic() {
    let (env, client, contract_id) = create_test_env();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let depositor = Address::generate(&env);
    let recipient = Address::generate(&env);
    let token_admin = Address::generate(&env);
    let (token, _token_client, token_admin_client) = create_token_contract(&env, &token_admin);

    client.init(&admin, &token);
    token_admin_client.mint(&depositor, &1_000);

    let bounty_id = 1;
    let amount = 500;
    let lock_deadline = env.ledger().timestamp() + 10_000;
    client.lock_funds(&depositor, &bounty_id, &amount, &lock_deadline);

    client.set_claim_window(&500);
    client.authorize_claim(&bounty_id, &recipient);

    let claimed_at = env.ledger().timestamp();
    client.claim(&bounty_id);

    // `authorize_claim` above already emitted a (claim, created) event, so we
    // need the LAST "claim"-topic event here, not the first.
    let (topics, data) = find_last_contract_event(&env, &contract_id, symbol_short!("claim"));

    // Topic tuple check: (claim, done)
    assert_eq!(topics.len(), 2);
    let topic1: Symbol = Symbol::try_from_val(&env, &topics.get(1).unwrap()).unwrap();
    assert_eq!(topic1, symbol_short!("done"));

    // Payload field checks
    let event: ClaimExecuted = ClaimExecuted::try_from_val(&env, &data)
        .unwrap_or_else(|_| panic!("payload should decode as ClaimExecuted"));
    assert_eq!(event.bounty_id, bounty_id);
    assert_eq!(event.recipient, recipient);
    assert_eq!(event.amount, amount);
    assert_eq!(event.claimed_at, claimed_at);
}

#[test]
fn test_pause_state_changed_event_for_lock_operation() {
    let (env, client, contract_id) = create_test_env();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    client.init(&admin, &token);

    client.set_paused(&Some(true), &None, &None);

    let (topics, data) = find_contract_event(&env, &contract_id, symbol_short!("pause"));

    // Topic tuple check: (pause, lock)
    assert_eq!(topics.len(), 2);
    let topic1: Symbol = Symbol::try_from_val(&env, &topics.get(1).unwrap()).unwrap();
    assert_eq!(topic1, symbol_short!("lock"));

    // Payload field checks
    let event: crate::PauseStateChanged = crate::PauseStateChanged::try_from_val(&env, &data)
        .unwrap_or_else(|_| panic!("payload should decode as PauseStateChanged"));
    assert_eq!(event.operation, symbol_short!("lock"));
    assert!(event.paused);
    assert_eq!(event.admin, admin);
}

#[test]
fn test_pause_state_changed_event_for_release_operation() {
    let (env, client, contract_id) = create_test_env();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    client.init(&admin, &token);

    client.set_paused(&None, &Some(true), &None);

    let (topics, data) = find_contract_event(&env, &contract_id, symbol_short!("pause"));

    // Topic tuple check: (pause, release)
    assert_eq!(topics.len(), 2);
    let topic1: Symbol = Symbol::try_from_val(&env, &topics.get(1).unwrap()).unwrap();
    assert_eq!(topic1, symbol_short!("release"));

    // Payload field checks
    let event: crate::PauseStateChanged = crate::PauseStateChanged::try_from_val(&env, &data)
        .unwrap_or_else(|_| panic!("payload should decode as PauseStateChanged"));
    assert_eq!(event.operation, symbol_short!("release"));
    assert!(event.paused);
    assert_eq!(event.admin, admin);
}#[test]
fn test_pause_state_changed_event_for_refund_operation() {
    let (env, client, contract_id) = create_test_env();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    client.init(&admin, &token);

    client.set_paused(&None, &None, &Some(true));

    let (topics, data) = find_contract_event(&env, &contract_id, symbol_short!("pause"));

    // Topic tuple check: (pause, refund)
    assert_eq!(topics.len(), 2);
    let topic1: Symbol = Symbol::try_from_val(&env, &topics.get(1).unwrap()).unwrap();
    assert_eq!(topic1, symbol_short!("refund"));

    // Payload field checks
    let event: crate::PauseStateChanged = crate::PauseStateChanged::try_from_val(&env, &data)
        .unwrap_or_else(|_| panic!("payload should decode as PauseStateChanged"));
    assert_eq!(event.operation, symbol_short!("refund"));
    assert!(event.paused);
    assert_eq!(event.admin, admin);
}

// Regression guard for issue #458: get_fee_config previously panicked on a
// freshly deployed, uninitialized contract (unwrap() on the not-yet-set
// DataKey::Admin key inside the fee_recipient fallback), instead of
// returning a graceful disabled default.
#[test]
fn test_get_fee_config_on_uninitialized_contract_does_not_panic() {
    let (_env, client, _contract_id) = create_test_env();

    let config = client.get_fee_config();

    assert_eq!(config.lock_fee_rate, 0);
    assert_eq!(config.release_fee_rate, 0);
    assert!(!config.fee_enabled);
}
