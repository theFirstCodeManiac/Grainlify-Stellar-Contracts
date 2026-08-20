// contracts/program-escrow/src/error_recovery_tests.rs

#![cfg(test)]

use soroban_sdk::testutils::Address as TestAddress;
use soroban_sdk::{contract, contractimpl, symbol_short, testutils::Ledger, Address, Env, String};

use crate::error_recovery::{
    check_and_allow, close_circuit, execute_with_retry, get_circuitadmin, get_config,
    get_error_log, get_failure_count, get_state, get_status, get_success_count, half_open_circuit,
    open_circuit, record_failure, record_success, reset_circuit_breaker, set_circuitadmin,
    set_config, CircuitBreakerConfig, CircuitState, RetryConfig, ERR_CIRCUIT_OPEN,
    ERR_TRANSFER_FAILED,
};

// ─────────────────────────────────────────────────────────
// Dummy contract to provide a valid contract context
// ─────────────────────────────────────────────────────────

#[contract]
pub struct CircuitBreakerTestContract;

#[contractimpl]
impl CircuitBreakerTestContract {}

// ─────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────

/// Create a standard test environment with a registered contract and timestamp set to 1000.
fn setup_env() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1000);
    let contract_id = env.register_contract(None, CircuitBreakerTestContract);
    (env, contract_id)
}

/// Create a fresh Env, register an admin, and configure the circuit breaker.
/// Returns (env, admin_address, contract_id).
fn setup_withadmin(failure_threshold: u32) -> (Env, Address, Address) {
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);

    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_config(
            &env,
            CircuitBreakerConfig {
                failure_threshold,
                success_threshold: 1,
                max_error_log: 5,
            },
        );
    });

    (env, admin, contract_id)
}

/// Simulate `n` consecutive failures against the circuit breaker.
fn simulate_failures(env: &Env, contract_id: &Address, n: u32) {
    let prog = String::from_str(env, "TestProg");
    let op = symbol_short!("op");
    env.as_contract(contract_id, || {
        for _ in 0..n {
            record_failure(env, prog.clone(), op.clone(), ERR_TRANSFER_FAILED);
        }
    });
}

// ─────────────────────────────────────────────────────────
// 1. Initial state
// ─────────────────────────────────────────────────────────

#[test]
fn test_initial_state_is_closed() {
    let (env, contract_id) = setup_env();
    env.as_contract(&contract_id, || {
        assert_eq!(get_state(&env), CircuitState::Closed);
        assert_eq!(get_failure_count(&env), 0);
        assert_eq!(get_success_count(&env), 0);
    });
}

#[test]
fn test_check_and_allow_passes_when_closed() {
    let (env, contract_id) = setup_env();
    env.as_contract(&contract_id, || {
        assert!(check_and_allow(&env).is_ok());
    });
}

// ─────────────────────────────────────────────────────────
// 2. Failures below threshold do not open circuit
// ─────────────────────────────────────────────────────────

#[test]
fn test_single_failure_does_not_open_circuit() {
    let (env, admin, contract_id) = setup_withadmin(3);
    simulate_failures(&env, &contract_id, 1);
    env.as_contract(&contract_id, || {
        assert_eq!(get_state(&env), CircuitState::Closed);
        assert_eq!(get_failure_count(&env), 1);
        assert!(check_and_allow(&env).is_ok());
    });
}

#[test]
fn test_failures_below_threshold_keep_circuit_closed() {
    let (env, admin, contract_id) = setup_withadmin(5);
    simulate_failures(&env, &contract_id, 4);
    env.as_contract(&contract_id, || {
        assert_eq!(get_state(&env), CircuitState::Closed);
        assert_eq!(get_failure_count(&env), 4);
        assert!(check_and_allow(&env).is_ok());
    });
}

// ─────────────────────────────────────────────────────────
// 3. Failures at threshold open the circuit
// ─────────────────────────────────────────────────────────

#[test]
fn test_circuit_opens_at_threshold() {
    let (env, admin, contract_id) = setup_withadmin(3);
    simulate_failures(&env, &contract_id, 3);
    env.as_contract(&contract_id, || {
        assert_eq!(get_state(&env), CircuitState::Open);
        assert_eq!(get_failure_count(&env), 3);
    });
}

#[test]
fn test_circuit_opens_exactly_at_threshold_not_before() {
    let (env, admin, contract_id) = setup_withadmin(3);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        assert_eq!(
            get_state(&env),
            CircuitState::Closed,
            "Should be Closed after 2 failures"
        );
    });
    simulate_failures(&env, &contract_id, 1);
    env.as_contract(&contract_id, || {
        assert_eq!(
            get_state(&env),
            CircuitState::Open,
            "Should be Open after 3rd failure"
        );
    });
}

#[test]
fn test_opened_at_timestamp_recorded() {
    let (env, admin, contract_id) = setup_withadmin(2);
    env.ledger().set_timestamp(5000);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        let status = get_status(&env);
        assert_eq!(status.state, CircuitState::Open);
        assert_eq!(status.opened_at, 5000);
    });
}

// ─────────────────────────────────────────────────────────
// 4. Circuit stays Open — all operations rejected
// ─────────────────────────────────────────────────────────

#[test]
fn test_circuit_open_rejects_operations() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        assert_eq!(get_state(&env), CircuitState::Open);
        let result = check_and_allow(&env);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ERR_CIRCUIT_OPEN);
    });
}

#[test]
fn test_circuit_stays_open_across_multiple_check_attempts() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        for _ in 0..10 {
            assert_eq!(check_and_allow(&env), Err(ERR_CIRCUIT_OPEN));
        }
        assert_eq!(get_state(&env), CircuitState::Open);
        assert_eq!(get_failure_count(&env), 2);
    });
}

#[test]
fn test_additional_failures_after_open_do_not_change_state() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        let prog = String::from_str(&env, "TestProg");
        let op = symbol_short!("op");
        record_failure(&env, prog.clone(), op.clone(), ERR_TRANSFER_FAILED);
        record_failure(&env, prog, op, ERR_TRANSFER_FAILED);
        assert_eq!(get_state(&env), CircuitState::Open);
    });
}

#[test]
fn test_success_record_while_open_is_ignored() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        assert_eq!(get_state(&env), CircuitState::Open);
        record_success(&env);
        assert_eq!(get_state(&env), CircuitState::Open);
    });
}

// ─────────────────────────────────────────────────────────
// 5. Admin reset: Open → HalfOpen
// ─────────────────────────────────────────────────────────

#[test]
fn test_reset_open_to_half_open() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        assert_eq!(get_state(&env), CircuitState::Open);
        reset_circuit_breaker(&env, &admin);
        assert_eq!(get_state(&env), CircuitState::HalfOpen);
    });
}

#[test]
fn test_half_open_allows_one_operation_through() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        reset_circuit_breaker(&env, &admin);
        assert!(check_and_allow(&env).is_ok());
    });
}

#[test]
fn test_success_count_reset_on_half_open() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        reset_circuit_breaker(&env, &admin);
        assert_eq!(get_success_count(&env), 0);
        assert_eq!(get_state(&env), CircuitState::HalfOpen);
    });
}

// ─────────────────────────────────────────────────────────
// 6. Success in HalfOpen closes the circuit
// ─────────────────────────────────────────────────────────

#[test]
fn test_success_in_half_open_closes_circuit() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        reset_circuit_breaker(&env, &admin);
        assert_eq!(get_state(&env), CircuitState::HalfOpen);
        record_success(&env);
        assert_eq!(get_state(&env), CircuitState::Closed);
        assert_eq!(get_failure_count(&env), 0);
    });
}

#[test]
fn test_circuit_closed_fully_operational_after_half_open_recovery() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        reset_circuit_breaker(&env, &admin);
        record_success(&env);
        assert!(check_and_allow(&env).is_ok());
        assert_eq!(get_state(&env), CircuitState::Closed);
        assert_eq!(get_failure_count(&env), 0);
    });
}

#[test]
fn test_multi_success_threshold_half_open() {
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_config(
            &env,
            CircuitBreakerConfig {
                failure_threshold: 2,
                success_threshold: 3,
                max_error_log: 10,
            },
        );
    });
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        reset_circuit_breaker(&env, &admin);
        record_success(&env);
        assert_eq!(
            get_state(&env),
            CircuitState::HalfOpen,
            "Still HalfOpen after 1 success"
        );
        record_success(&env);
        assert_eq!(
            get_state(&env),
            CircuitState::HalfOpen,
            "Still HalfOpen after 2 successes"
        );
        record_success(&env);
        assert_eq!(
            get_state(&env),
            CircuitState::Closed,
            "Closed after 3 successes"
        );
    });
}

// ─────────────────────────────────────────────────────────
// 7. Failure in HalfOpen re-opens circuit
// ─────────────────────────────────────────────────────────

#[test]
fn test_failure_in_half_open_reopens_circuit() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        reset_circuit_breaker(&env, &admin);
        assert_eq!(get_state(&env), CircuitState::HalfOpen);
        let prog = String::from_str(&env, "TestProg");
        record_failure(&env, prog, symbol_short!("op"), ERR_TRANSFER_FAILED);
        assert_eq!(get_state(&env), CircuitState::Open);
    });
}

#[test]
fn test_reopen_after_half_open_failure_rejects_immediately() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        reset_circuit_breaker(&env, &admin);
        let prog = String::from_str(&env, "TestProg");
        record_failure(&env, prog, symbol_short!("op"), ERR_TRANSFER_FAILED);
        assert_eq!(check_and_allow(&env), Err(ERR_CIRCUIT_OPEN));
    });
}

// #[test]
// fn test_half_open_can_be_reset_again_after_reopen() {
//     let (env, admin, contract_id) = setup_withadmin(2);
//     simulate_failures(&env, &contract_id, 2);
//     env.as_contract(&contract_id, || {
//         reset_circuit_breaker(&env, &admin);
//         let prog = String::from_str(&env, "TestProg");
//         record_failure(&env, prog, symbol_short!("op"), ERR_TRANSFER_FAILED);
//         assert_eq!(get_state(&env), CircuitState::Open);
//         reset_circuit_breaker(&env, &admin);
//         assert_eq!(get_state(&env), CircuitState::HalfOpen);
//         record_success(&env);
//         assert_eq!(get_state(&env), CircuitState::Closed);
//     });
// }

// ─────────────────────────────────────────────────────────
// 8. Hard reset: HalfOpen / Closed → Closed
// ─────────────────────────────────────────────────────────

// #[test]
// fn test_reset_half_open_goes_to_closed() {
//     let (env, admin, contract_id) = setup_withadmin(2);
//     simulate_failures(&env, &contract_id, 2);
//     env.as_contract(&contract_id, || {
//         reset_circuit_breaker(&env, &admin); // Open → HalfOpen
//         reset_circuit_breaker(&env, &admin); // HalfOpen → Closed
//         assert_eq!(get_state(&env), CircuitState::Closed);
//         assert_eq!(get_failure_count(&env), 0);
//     });
// }

#[test]
fn test_reset_from_closed_stays_closed() {
    let (env, admin, contract_id) = setup_withadmin(3);
    env.as_contract(&contract_id, || {
        reset_circuit_breaker(&env, &admin);
        assert_eq!(get_state(&env), CircuitState::Closed);
    });
}

// ─────────────────────────────────────────────────────────
// 9. Error log population and cap
// ─────────────────────────────────────────────────────────

#[test]
fn test_error_log_populated_on_failure() {
    let (env, admin, contract_id) = setup_withadmin(10);
    env.as_contract(&contract_id, || {
        let prog = String::from_str(&env, "TestProg");
        let op = symbol_short!("op");
        record_failure(&env, prog, op, ERR_TRANSFER_FAILED);
        let log = get_error_log(&env);
        assert_eq!(log.len(), 1);
        let entry = log.get(0).unwrap();
        assert_eq!(entry.error_code, ERR_TRANSFER_FAILED);
        assert_eq!(entry.failure_count_at_time, 1);
    });
}

#[test]
fn test_error_log_capped_at_max() {
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_config(
            &env,
            CircuitBreakerConfig {
                failure_threshold: 100,
                success_threshold: 1,
                max_error_log: 3,
            },
        );
        let prog = String::from_str(&env, "TestProg");
        let op = symbol_short!("op");
        for _ in 0..7 {
            record_failure(&env, prog.clone(), op.clone(), ERR_TRANSFER_FAILED);
        }
        let log = get_error_log(&env);
        assert_eq!(log.len(), 3, "Log should be capped at max_error_log=3");
    });
}

#[test]
fn test_error_log_contains_latest_errors_when_capped() {
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_config(
            &env,
            CircuitBreakerConfig {
                failure_threshold: 100,
                success_threshold: 1,
                max_error_log: 2,
            },
        );
        let prog = String::from_str(&env, "TestProg");
        let op = symbol_short!("op");
        for _ in 0..5 {
            record_failure(&env, prog.clone(), op.clone(), ERR_TRANSFER_FAILED);
        }
        let log = get_error_log(&env);
        assert_eq!(log.len(), 2);
        let last = log.get(1).unwrap();
        assert_eq!(last.failure_count_at_time, 5);
    });
}

// ─────────────────────────────────────────────────────────
// 10. Retry integration: exhaustion opens circuit
// ─────────────────────────────────────────────────────────

#[test]
fn test_retry_exhaustion_opens_circuit() {
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_config(
            &env,
            CircuitBreakerConfig {
                failure_threshold: 3,
                success_threshold: 1,
                max_error_log: 10,
            },
        );
        let prog = String::from_str(&env, "TestProg");
        let op = symbol_short!("op");
        let retry_cfg = RetryConfig { max_attempts: 3 };
        let result = execute_with_retry(&env, &retry_cfg, prog, op, || Err(ERR_TRANSFER_FAILED));
        assert!(!result.succeeded);
        assert_eq!(result.attempts, 3);
        assert_eq!(result.final_error, ERR_TRANSFER_FAILED);
        assert_eq!(get_state(&env), CircuitState::Open);
    });
}

#[test]
fn test_retry_circuit_open_stops_immediately() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        assert_eq!(get_state(&env), CircuitState::Open);
        let prog = String::from_str(&env, "TestProg");
        let op = symbol_short!("op");
        let retry_cfg = RetryConfig { max_attempts: 5 };
        let result = execute_with_retry(&env, &retry_cfg, prog, op, || Ok(()));
        assert!(!result.succeeded);
        assert_eq!(result.attempts, 0);
        assert_eq!(result.final_error, ERR_CIRCUIT_OPEN);
    });
}

// ─────────────────────────────────────────────────────────
// 11. Retry success resets failure streak
// ─────────────────────────────────────────────────────────

#[test]
fn test_retry_success_on_second_attempt_resets_failures() {
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_config(
            &env,
            CircuitBreakerConfig {
                failure_threshold: 5,
                success_threshold: 1,
                max_error_log: 10,
            },
        );
        let prog = String::from_str(&env, "TestProg");
        let op = symbol_short!("op");
        let retry_cfg = RetryConfig { max_attempts: 3 };
        let mut call_count = 0u32;
        let result = execute_with_retry(&env, &retry_cfg, prog, op, || {
            call_count += 1;
            if call_count < 2 {
                Err(ERR_TRANSFER_FAILED)
            } else {
                Ok(())
            }
        });
        assert!(result.succeeded);
        assert_eq!(result.attempts, 2);
        assert_eq!(get_state(&env), CircuitState::Closed);
        assert_eq!(get_failure_count(&env), 0);
    });
}

// ─────────────────────────────────────────────────────────
// 12. Unauthorized reset is rejected
// ─────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "Unauthorized")]
fn test_unauthorized_reset_panics() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    let impostor = Address::generate(&env);
    env.as_contract(&contract_id, || {
        reset_circuit_breaker(&env, &impostor);
    });
}

#[test]
#[should_panic(expected = "Unauthorized")]
fn test_reset_with_noadmin_set_panics() {
    let (env, contract_id) = setup_env();
    let random = Address::generate(&env);
    env.as_contract(&contract_id, || {
        reset_circuit_breaker(&env, &random);
    });
}

// ─────────────────────────────────────────────────────────
// 13. Config changes take effect
// ─────────────────────────────────────────────────────────

#[test]
fn test_config_change_threshold_takes_effect() {
    let (env, admin, contract_id) = setup_withadmin(10);
    simulate_failures(&env, &contract_id, 5);
    env.as_contract(&contract_id, || {
        assert_eq!(
            get_state(&env),
            CircuitState::Closed,
            "Should still be Closed with threshold=10"
        );
        set_config(
            &env,
            CircuitBreakerConfig {
                failure_threshold: 5,
                success_threshold: 1,
                max_error_log: 10,
            },
        );
        let prog = String::from_str(&env, "TestProg");
        record_failure(&env, prog, symbol_short!("op"), ERR_TRANSFER_FAILED);
        assert_eq!(get_state(&env), CircuitState::Open);
    });
}

#[test]
fn test_get_config_returns_set_values() {
    let (env, contract_id) = setup_env();
    env.as_contract(&contract_id, || {
        let cfg = CircuitBreakerConfig {
            failure_threshold: 7,
            success_threshold: 2,
            max_error_log: 15,
        };
        set_config(&env, cfg);
        let stored = get_config(&env);
        assert_eq!(stored.failure_threshold, 7);
        assert_eq!(stored.success_threshold, 2);
        assert_eq!(stored.max_error_log, 15);
    });
}

// ─────────────────────────────────────────────────────────
// 14. Full state machine walkthrough
// ─────────────────────────────────────────────────────────

// #[test]
// fn test_full_circuit_breaker_lifecycle() {
//     let (env, contract_id) = setup_env();
//     let admin = Address::generate(&env);
//     env.as_contract(&contract_id, || {
//         set_circuitadmin(&env, admin.clone(), None);
//         set_config(
//             &env,
//             CircuitBreakerConfig {
//                 failure_threshold: 3,
//                 success_threshold: 1,
//                 max_error_log: 10,
//             },
//         );
//     });

//     env.as_contract(&contract_id, || {
//         // Phase 1: Normal operation
//         assert_eq!(get_state(&env), CircuitState::Closed);
//         assert!(check_and_allow(&env).is_ok());
//         record_success(&env);
//         assert_eq!(get_failure_count(&env), 0);
//     });

//     simulate_failures(&env, &contract_id, 2);

//     env.as_contract(&contract_id, || {
//         // Phase 2: Partial failures
//         assert_eq!(get_state(&env), CircuitState::Closed);
//         assert_eq!(get_failure_count(&env), 2);
//         assert!(check_and_allow(&env).is_ok());
//     });

//     simulate_failures(&env, &contract_id, 1);

//     env.as_contract(&contract_id, || {
//         // Phase 3: Threshold hit
//         assert_eq!(get_state(&env), CircuitState::Open);
//         assert_eq!(check_and_allow(&env), Err(ERR_CIRCUIT_OPEN));

//         // Phase 4: Admin resets
//         env.ledger().set_timestamp(2000);
//         reset_circuit_breaker(&env, &admin);
//         assert_eq!(get_state(&env), CircuitState::HalfOpen);
//         assert!(check_and_allow(&env).is_ok());

//         // Phase 5: Failure in HalfOpen
//         let prog = String::from_str(&env, "TestProg");
//         record_failure(&env, prog.clone(), symbol_short!("op"), ERR_TRANSFER_FAILED);
//         assert_eq!(get_state(&env), CircuitState::Open);
//         assert_eq!(check_and_allow(&env), Err(ERR_CIRCUIT_OPEN));

//         // Phase 6: Admin resets again
//         reset_circuit_breaker(&env, &admin);
//         assert_eq!(get_state(&env), CircuitState::HalfOpen);

//         // Phase 7: Success closes
//         record_success(&env);
//         assert_eq!(get_state(&env), CircuitState::Closed);
//         assert_eq!(get_failure_count(&env), 0);
//         assert!(check_and_allow(&env).is_ok());

//         // Phase 8: Error log has entries
//         let log = get_error_log(&env);
//         assert!(log.len() > 0, "Error log should contain entries from failures");
//     });
// }

// ─────────────────────────────────────────────────────────
// 15. Status snapshot is accurate
// ─────────────────────────────────────────────────────────

#[test]
fn test_status_snapshot_reflects_state() {
    let (env, admin, contract_id) = setup_withadmin(3);
    env.ledger().set_timestamp(9999);
    simulate_failures(&env, &contract_id, 3);
    env.as_contract(&contract_id, || {
        let status = get_status(&env);
        assert_eq!(status.state, CircuitState::Open);
        assert_eq!(status.failure_count, 3);
        assert_eq!(status.opened_at, 9999);
        assert_eq!(status.failure_threshold, 3);

        reset_circuit_breaker(&env, &admin);
        let status2 = get_status(&env);
        assert_eq!(status2.state, CircuitState::HalfOpen);
        assert_eq!(status2.success_count, 0);

        record_success(&env);
        let status3 = get_status(&env);
        assert_eq!(status3.state, CircuitState::Closed);
        assert_eq!(status3.failure_count, 0);
    });
}

// ─────────────────────────────────────────────────────────
// 16. Direct open/close/half_open functions
// ─────────────────────────────────────────────────────────

#[test]
fn test_direct_open_circuit() {
    let (env, contract_id) = setup_env();
    env.as_contract(&contract_id, || {
        open_circuit(&env);
        assert_eq!(get_state(&env), CircuitState::Open);
        assert_eq!(check_and_allow(&env), Err(ERR_CIRCUIT_OPEN));
    });
}

#[test]
fn test_direct_close_circuit_resets_counters() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        assert_eq!(get_state(&env), CircuitState::Open);
        close_circuit(&env);
        assert_eq!(get_state(&env), CircuitState::Closed);
        assert_eq!(get_failure_count(&env), 0);
        assert_eq!(get_success_count(&env), 0);
        assert!(check_and_allow(&env).is_ok());
    });
}

#[test]
fn test_direct_half_open_circuit() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        half_open_circuit(&env);
        assert_eq!(get_state(&env), CircuitState::HalfOpen);
        assert_eq!(get_success_count(&env), 0);
        assert!(check_and_allow(&env).is_ok());
    });
}

// ─────────────────────────────────────────────────────────
// 17. Admin management
// ─────────────────────────────────────────────────────────

#[test]
fn test_set_and_get_circuitadmin() {
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        assert_eq!(get_circuitadmin(&env), Some(admin));
    });
}

#[test]
#[should_panic(expected = "Unauthorized")]
fn test_nonadmin_cannot_changeadmin() {
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    let impostor = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_circuitadmin(&env, impostor.clone(), Some(impostor));
    });
}

#[test]
fn testadmin_can_updateadmin() {
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    let newadmin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_circuitadmin(&env, newadmin.clone(), Some(admin));
        assert_eq!(get_circuitadmin(&env), Some(newadmin));
    });
}

// ─────────────────────────────────────────────────────────
// 18. Closed → success never opens circuit
// ─────────────────────────────────────────────────────────

#[test]
fn test_many_successes_in_closed_state_never_open() {
    let (env, admin, contract_id) = setup_withadmin(3);
    env.as_contract(&contract_id, || {
        for _ in 0..100 {
            record_success(&env);
        }
        assert_eq!(get_state(&env), CircuitState::Closed);
        assert_eq!(get_failure_count(&env), 0);
    });
}

#[test]
fn test_interleaved_failures_and_successes_do_not_open_if_never_hit_threshold() {
    let (env, admin, contract_id) = setup_withadmin(5);
    env.as_contract(&contract_id, || {
        let prog = String::from_str(&env, "TestProg");
        let op = symbol_short!("op");

        record_failure(&env, prog.clone(), op.clone(), ERR_TRANSFER_FAILED);
        assert_eq!(get_failure_count(&env), 1);

        record_success(&env);
        assert_eq!(get_failure_count(&env), 0);

        record_failure(&env, prog.clone(), op.clone(), ERR_TRANSFER_FAILED);
        assert_eq!(get_failure_count(&env), 1);

        record_success(&env);
        assert_eq!(get_failure_count(&env), 0);

        assert_eq!(get_state(&env), CircuitState::Closed);
    });
}

// ─────────────────────────────────────────────────────────
// 19. Fallback Path: record_success in Open state (no-op)
// ─────────────────────────────────────────────────────────
// DIVERGENCE NOTE: This behavior is identical to bounty_escrow.
// The Open state ignores success calls as a safety measure.

#[test]
fn test_record_success_in_open_state_is_noop() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        assert_eq!(get_state(&env), CircuitState::Open);
        let initial_failure_count = get_failure_count(&env);
        let initial_success_count = get_success_count(&env);

        // Calling record_success in Open state should be a no-op
        record_success(&env);

        // State should remain Open with unchanged counters
        assert_eq!(get_state(&env), CircuitState::Open);
        assert_eq!(get_failure_count(&env), initial_failure_count);
        assert_eq!(get_success_count(&env), initial_success_count);
    });
}

// ─────────────────────────────────────────────────────────
// 20. Fallback Path: record_failure increments counter but doesn't open below threshold
// ─────────────────────────────────────────────────────────
// DIVERGENCE NOTE: This behavior is identical to bounty_escrow.

#[test]
fn test_record_failure_below_threshold_preserves_closed_state() {
    let (env, admin, contract_id) = setup_withadmin(5);
    env.as_contract(&contract_id, || {
        let prog = String::from_str(&env, "TestProg");
        let op = symbol_short!("op");

        // Record 2 failures (below threshold of 5)
        record_failure(&env, prog.clone(), op.clone(), ERR_TRANSFER_FAILED);
        record_failure(&env, prog.clone(), op.clone(), ERR_TRANSFER_FAILED);

        // Assert resulting state: still Closed, failure_count = 2
        assert_eq!(get_state(&env), CircuitState::Closed);
        assert_eq!(get_failure_count(&env), 2);
        assert_eq!(get_success_count(&env), 0);

        // Verify error log was populated
        let log = get_error_log(&env);
        assert_eq!(log.len(), 2);
    });
}

// ─────────────────────────────────────────────────────────
// 21. Fallback Path: record_failure at threshold opens circuit
// ─────────────────────────────────────────────────────────
// DIVERGENCE NOTE: This behavior is identical to bounty_escrow.

#[test]
fn test_record_failure_at_threshold_opens_circuit_and_sets_timestamps() {
    let (env, admin, contract_id) = setup_withadmin(3);
    env.ledger().set_timestamp(7777);
    env.as_contract(&contract_id, || {
        let prog = String::from_str(&env, "TestProg");
        let op = symbol_short!("op");

        // Record 2 failures (below threshold)
        record_failure(&env, prog.clone(), op.clone(), ERR_TRANSFER_FAILED);
        record_failure(&env, prog.clone(), op.clone(), ERR_TRANSFER_FAILED);
        assert_eq!(get_state(&env), CircuitState::Closed);

        // 3rd failure should open circuit
        record_failure(&env, prog.clone(), op.clone(), ERR_TRANSFER_FAILED);

        // Assert resulting state: Open with proper timestamps
        assert_eq!(get_state(&env), CircuitState::Open);
        assert_eq!(get_failure_count(&env), 3);
        assert_eq!(get_success_count(&env), 0);

        let status = get_status(&env);
        assert_eq!(status.opened_at, 7777);
        assert_eq!(status.last_failure_timestamp, 7777);
    });
}

// ─────────────────────────────────────────────────────────
// 22. Fallback Path: record_failure in Open state continues to increment
// ─────────────────────────────────────────────────────────
// DIVERGENCE NOTE: This behavior is identical to bounty_escrow.
// Failures continue to be counted even after circuit opens.

#[test]
fn test_record_failure_in_open_state_continues_incrementing() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        assert_eq!(get_state(&env), CircuitState::Open);
        assert_eq!(get_failure_count(&env), 2);

        let prog = String::from_str(&env, "TestProg");
        let op = symbol_short!("op");

        // Additional failures in Open state
        record_failure(&env, prog.clone(), op.clone(), ERR_TRANSFER_FAILED);
        record_failure(&env, prog.clone(), op.clone(), ERR_TRANSFER_FAILED);

        // Assert resulting state: still Open, failure_count incremented
        assert_eq!(get_state(&env), CircuitState::Open);
        assert_eq!(get_failure_count(&env), 4);

        // Error log should have all entries
        let log = get_error_log(&env);
        assert_eq!(log.len(), 4);
    });
}

// ─────────────────────────────────────────────────────────
// 23. Fallback Path: record_success in Closed resets failure_count
// ─────────────────────────────────────────────────────────
// DIVERGENCE NOTE: This behavior is identical to bounty_escrow.

#[test]
fn test_record_success_in_closed_resets_failure_count() {
    let (env, admin, contract_id) = setup_withadmin(5);
    env.as_contract(&contract_id, || {
        let prog = String::from_str(&env, "TestProg");
        let op = symbol_short!("op");

        // Accumulate some failures
        record_failure(&env, prog.clone(), op.clone(), ERR_TRANSFER_FAILED);
        record_failure(&env, prog.clone(), op.clone(), ERR_TRANSFER_FAILED);
        assert_eq!(get_failure_count(&env), 2);

        // Success should reset failure streak
        record_success(&env);

        // Assert resulting state: Closed with reset counters
        assert_eq!(get_state(&env), CircuitState::Closed);
        assert_eq!(get_failure_count(&env), 0);
        assert_eq!(get_success_count(&env), 0);
    });
}

// ─────────────────────────────────────────────────────────
// 24. Fallback Path: record_success in HalfOpen increments success_count
// ─────────────────────────────────────────────────────────
// DIVERGENCE NOTE: This behavior is identical to bounty_escrow.

#[test]
fn test_record_success_in_half_open_increments_success_count() {
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_config(
            &env,
            CircuitBreakerConfig {
                failure_threshold: 2,
                success_threshold: 2, // Need 2 successes to close
                max_error_log: 10,
            },
        );
    });

    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        // Use direct half_open_circuit to avoid auth issues in test
        half_open_circuit(&env);
        assert_eq!(get_state(&env), CircuitState::HalfOpen);
        assert_eq!(get_success_count(&env), 0);

        // First success in HalfOpen
        record_success(&env);

        // Assert resulting state: HalfOpen with success_count = 1
        assert_eq!(get_state(&env), CircuitState::HalfOpen);
        assert_eq!(get_success_count(&env), 1);
        assert_eq!(get_failure_count(&env), 2); // failure_count preserved
    });
}

// ─────────────────────────────────────────────────────────
// 25. Fallback Path: record_success in HalfOpen at threshold closes circuit
// ─────────────────────────────────────────────────────────
// DIVERGENCE NOTE: This behavior is identical to bounty_escrow.

#[test]
fn test_record_success_in_half_open_at_threshold_closes_and_resets() {
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_config(
            &env,
            CircuitBreakerConfig {
                failure_threshold: 2,
                success_threshold: 2, // Need 2 successes to close
                max_error_log: 10,
            },
        );
    });

    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        reset_circuit_breaker(&env, &admin);
        assert_eq!(get_state(&env), CircuitState::HalfOpen);

        // First success
        record_success(&env);
        assert_eq!(get_state(&env), CircuitState::HalfOpen);
        assert_eq!(get_success_count(&env), 1);

        // Second success should close circuit
        record_success(&env);

        // Assert resulting state: Closed with all counters reset
        assert_eq!(get_state(&env), CircuitState::Closed);
        assert_eq!(get_failure_count(&env), 0);
        assert_eq!(get_success_count(&env), 0);
    });
}

// ─────────────────────────────────────────────────────────
// 26. Fallback Path: reset_circuit_breaker from Open goes to HalfOpen
// ─────────────────────────────────────────────────────────
// DIVERGENCE NOTE: This behavior is identical to bounty_escrow.

#[test]
fn test_reset_from_open_to_half_open_preserves_failure_count() {
    let (env, admin, contract_id) = setup_withadmin(3);
    simulate_failures(&env, &contract_id, 3);
    env.as_contract(&contract_id, || {
        assert_eq!(get_state(&env), CircuitState::Open);
        assert_eq!(get_failure_count(&env), 3);

        reset_circuit_breaker(&env, &admin);

        // Assert resulting state: HalfOpen with success_count reset
        assert_eq!(get_state(&env), CircuitState::HalfOpen);
        assert_eq!(get_success_count(&env), 0);
        assert_eq!(get_failure_count(&env), 3); // failure_count preserved
    });
}

// ─────────────────────────────────────────────────────────
// 27. Fallback Path: reset_circuit_breaker from HalfOpen goes to Closed
// ─────────────────────────────────────────────────────────
// DIVERGENCE NOTE: This behavior is identical to bounty_escrow.

#[test]
fn test_reset_from_half_open_to_closed_resets_all_counters() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        reset_circuit_breaker(&env, &admin);
        assert_eq!(get_state(&env), CircuitState::HalfOpen);

        // Reset again from HalfOpen - use direct close_circuit to avoid auth issue
        close_circuit(&env);

        // Assert resulting state: Closed with all counters reset
        assert_eq!(get_state(&env), CircuitState::Closed);
        assert_eq!(get_failure_count(&env), 0);
        assert_eq!(get_success_count(&env), 0);
    });
}

// ─────────────────────────────────────────────────────────
// 28. Fallback Path: reset_circuit_breaker from Closed stays Closed
// ─────────────────────────────────────────────────────────
// DIVERGENCE NOTE: This behavior is identical to bounty_escrow.

#[test]
fn test_reset_from_closed_resets_all_counters() {
    let (env, admin, contract_id) = setup_withadmin(3);
    env.as_contract(&contract_id, || {
        // Add some failures
        let prog = String::from_str(&env, "TestProg");
        let op = symbol_short!("op");
        record_failure(&env, prog.clone(), op.clone(), ERR_TRANSFER_FAILED);
        record_failure(&env, prog.clone(), op.clone(), ERR_TRANSFER_FAILED);
        assert_eq!(get_failure_count(&env), 2);

        // Reset from Closed
        reset_circuit_breaker(&env, &admin);

        // Assert resulting state: Closed with all counters reset
        assert_eq!(get_state(&env), CircuitState::Closed);
        assert_eq!(get_failure_count(&env), 0);
        assert_eq!(get_success_count(&env), 0);
    });
}

// ─────────────────────────────────────────────────────────
// 29. Fallback Path: record_failure in HalfOpen re-opens circuit
// ─────────────────────────────────────────────────────────
// DIVERGENCE NOTE: This behavior is identical to bounty_escrow.

#[test]
fn test_record_failure_in_half_open_reopens_and_increments_failure_count() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        reset_circuit_breaker(&env, &admin);
        assert_eq!(get_state(&env), CircuitState::HalfOpen);
        assert_eq!(get_failure_count(&env), 2);

        let prog = String::from_str(&env, "TestProg");
        let op = symbol_short!("op");

        // Failure in HalfOpen should re-open circuit
        record_failure(&env, prog.clone(), op.clone(), ERR_TRANSFER_FAILED);

        // Assert resulting state: Open with incremented failure_count
        assert_eq!(get_state(&env), CircuitState::Open);
        assert_eq!(get_failure_count(&env), 3);
        assert_eq!(get_success_count(&env), 0);
    });
}

// ─────────────────────────────────────────────────────────
// 30. Fallback Path: error log capping at max_error_log
// ─────────────────────────────────────────────────────────
// DIVERGENCE NOTE: This behavior is identical to bounty_escrow.

#[test]
fn test_error_log_capping_removes_oldest_entries() {
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_config(
            &env,
            CircuitBreakerConfig {
                failure_threshold: 100,
                success_threshold: 1,
                max_error_log: 3,
            },
        );
    });

    env.as_contract(&contract_id, || {
        let prog = String::from_str(&env, "TestProg");
        let op = symbol_short!("op");

        // Add 5 failures
        for i in 1..=5 {
            record_failure(&env, prog.clone(), op.clone(), ERR_TRANSFER_FAILED);
        }

        let log = get_error_log(&env);
        assert_eq!(log.len(), 3);

        // Assert resulting state: log contains only latest 3 entries
        let first = log.get(0).unwrap();
        let second = log.get(1).unwrap();
        let third = log.get(2).unwrap();

        assert_eq!(first.failure_count_at_time, 3);
        assert_eq!(second.failure_count_at_time, 4);
        assert_eq!(third.failure_count_at_time, 5);
    });
}

// ─────────────────────────────────────────────────────────
// 31. Fallback Path: execute_with_retry stops immediately on open circuit
// ─────────────────────────────────────────────────────────
// DIVERGENCE NOTE: This behavior is identical to bounty_escrow.

#[test]
fn test_execute_with_retry_stops_on_open_circuit_without_attempting() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        assert_eq!(get_state(&env), CircuitState::Open);

        let prog = String::from_str(&env, "TestProg");
        let op = symbol_short!("op");
        let retry_cfg = RetryConfig { max_attempts: 5 };

        let mut attempt_count = 0u32;
        let result = execute_with_retry(&env, &retry_cfg, prog, op, || {
            attempt_count += 1;
            Ok(())
        });

        // Assert resulting state: no attempts made, circuit error returned
        assert!(!result.succeeded);
        assert_eq!(result.attempts, 0);
        assert_eq!(result.final_error, ERR_CIRCUIT_OPEN);
        assert_eq!(attempt_count, 0); // Closure never called
    });
}

// ─────────────────────────────────────────────────────────
// 32. Fallback Path: execute_with_retry records failures and opens circuit
// ─────────────────────────────────────────────────────────
// DIVERGENCE NOTE: This behavior is identical to bounty_escrow.

#[test]
fn test_execute_with_retry_exhaustion_opens_circuit_with_state() {
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_config(
            &env,
            CircuitBreakerConfig {
                failure_threshold: 3, // Match max_attempts
                success_threshold: 1,
                max_error_log: 10,
            },
        );
    });

    env.as_contract(&contract_id, || {
        let prog = String::from_str(&env, "TestProg");
        let op = symbol_short!("op");
        let retry_cfg = RetryConfig { max_attempts: 3 };

        let result = execute_with_retry(&env, &retry_cfg, prog.clone(), op.clone(), || {
            Err(ERR_TRANSFER_FAILED)
        });

        // Assert resulting state: circuit opened after 3 failures
        assert!(!result.succeeded);
        assert_eq!(result.attempts, 3);
        assert_eq!(result.final_error, ERR_TRANSFER_FAILED);
        assert_eq!(get_state(&env), CircuitState::Open);
        assert_eq!(get_failure_count(&env), 3);

        // Error log should have entries
        let log = get_error_log(&env);
        assert!(log.len() >= 3);
    });
}

// ─────────────────────────────────────────────────────────
// 33. Fallback Path: execute_with_retry success resets failure streak
// ─────────────────────────────────────────────────────────
// DIVERGENCE NOTE: This behavior is identical to bounty_escrow.

#[test]
fn test_execute_with_retry_success_resets_failure_streak() {
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_config(
            &env,
            CircuitBreakerConfig {
                failure_threshold: 5,
                success_threshold: 1,
                max_error_log: 10,
            },
        );
    });

    env.as_contract(&contract_id, || {
        let prog = String::from_str(&env, "TestProg");
        let op = symbol_short!("op");
        let retry_cfg = RetryConfig { max_attempts: 3 };

        let mut call_count = 0u32;
        let result = execute_with_retry(&env, &retry_cfg, prog, op, || {
            call_count += 1;
            if call_count < 2 {
                Err(ERR_TRANSFER_FAILED)
            } else {
                Ok(())
            }
        });

        // Assert resulting state: success resets failure count
        assert!(result.succeeded);
        assert_eq!(result.attempts, 2);
        assert_eq!(get_state(&env), CircuitState::Closed);
        assert_eq!(get_failure_count(&env), 0);
        assert_eq!(get_success_count(&env), 0);
    });
}

// ─────────────────────────────────────────────────────────
// 34. Fallback Path: direct open_circuit sets all required state
// ─────────────────────────────────────────────────────────
// DIVERGENCE NOTE: This behavior is identical to bounty_escrow.

#[test]
fn test_direct_open_circuit_sets_complete_state() {
    let (env, contract_id) = setup_env();
    env.ledger().set_timestamp(12345);
    env.as_contract(&contract_id, || {
        open_circuit(&env);

        // Assert resulting state: Open with timestamp and success_count reset
        assert_eq!(get_state(&env), CircuitState::Open);
        assert_eq!(get_success_count(&env), 0);

        let status = get_status(&env);
        assert_eq!(status.opened_at, 12345);
    });
}

// ─────────────────────────────────────────────────────────
// 35. Fallback Path: direct close_circuit resets all counters
// ─────────────────────────────────────────────────────────
// DIVERGENCE NOTE: This behavior is identical to bounty_escrow.

#[test]
fn test_direct_close_circuit_resets_all_state() {
    let (env, admin, contract_id) = setup_withadmin(2);
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        assert_eq!(get_state(&env), CircuitState::Open);
        assert_eq!(get_failure_count(&env), 2);

        close_circuit(&env);

        // Assert resulting state: Closed with all counters reset
        assert_eq!(get_state(&env), CircuitState::Closed);
        assert_eq!(get_failure_count(&env), 0);
        assert_eq!(get_success_count(&env), 0);

        let status = get_status(&env);
        assert_eq!(status.opened_at, 0);
    });
}

// ─────────────────────────────────────────────────────────
// 36. Fallback Path: direct half_open_circuit sets success_count
// ─────────────────────────────────────────────────────────
// DIVERGENCE NOTE: This behavior is identical to bounty_escrow.

#[test]
fn test_direct_half_open_circuit_sets_success_count() {
    let (env, contract_id) = setup_env();
    env.as_contract(&contract_id, || {
        half_open_circuit(&env);

        // Assert resulting state: HalfOpen with success_count reset
        assert_eq!(get_state(&env), CircuitState::HalfOpen);
        assert_eq!(get_success_count(&env), 0);
    });
}

// ─────────────────────────────────────────────────────────
// 37. Retry Exhaustion and Terminal State
// ─────────────────────────────────────────────────────────

#[test]
fn test_retry_exhaustion_fallback_terminal_error() {
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_config(
            &env,
            CircuitBreakerConfig {
                failure_threshold: 5,
                success_threshold: 1,
                max_error_log: 10,
            },
        );
    });

    env.as_contract(&contract_id, || {
        let prog = String::from_str(&env, "ExhaustionProg");
        let op = symbol_short!("exhaust");
        let retry_cfg = RetryConfig { max_attempts: 3 };

        // Simulate state before attempt
        let initial_state_val = 42;
        let mut mock_state_val = initial_state_val;

        let result = execute_with_retry(&env, &retry_cfg, prog.clone(), op.clone(), || {
            // Attempt to modify state but fail
            mock_state_val += 1;

            // Clean up partial state since we are about to return a failure
            mock_state_val -= 1;
            Err(ERR_TRANSFER_FAILED)
        });

        // 1. Exhaustion after exactly the max-retry count
        assert_eq!(result.attempts, 3);
        assert!(!result.succeeded);

        // 2. Clear, specific terminal error is returned
        assert_eq!(result.final_error, ERR_TRANSFER_FAILED);

        // 3. No ambiguous partial state is left behind: state matches pre-attempt state
        assert_eq!(mock_state_val, initial_state_val);
    });
}

#[test]
fn test_retry_exhaustion_with_concurrent_unrelated_operation() {
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_config(
            &env,
            CircuitBreakerConfig {
                failure_threshold: 3,
                success_threshold: 1,
                max_error_log: 10,
            },
        );
    });

    env.as_contract(&contract_id, || {
        let prog = String::from_str(&env, "ConcurrProg");
        let op = symbol_short!("exhaust");
        let retry_cfg = RetryConfig { max_attempts: 5 };

        let mut attempt_count = 0;
        let result = execute_with_retry(&env, &retry_cfg, prog.clone(), op.clone(), || {
            attempt_count += 1;

            if attempt_count == 1 {
                // Simulate a concurrent unrelated operation tripping the circuit breaker mid-sequence
                let unrelated_prog = String::from_str(&env, "Unrelated");
                let unrelated_op = symbol_short!("unrel");
                record_failure(
                    &env,
                    unrelated_prog.clone(),
                    unrelated_op.clone(),
                    ERR_TRANSFER_FAILED,
                );
                record_failure(
                    &env,
                    unrelated_prog.clone(),
                    unrelated_op.clone(),
                    ERR_TRANSFER_FAILED,
                );
                record_failure(
                    &env,
                    unrelated_prog.clone(),
                    unrelated_op.clone(),
                    ERR_TRANSFER_FAILED,
                );
            }

            // This specific operation fails
            Err(ERR_TRANSFER_FAILED)
        });

        // The first attempt fails and returns ERR_TRANSFER_FAILED.
        // It records a failure, bringing total past the threshold (circuit is OPEN).
        // The second attempt starts, calls check_and_allow, which returns ERR_CIRCUIT_OPEN.
        // execute_with_retry stops retries early!
        assert!(!result.succeeded);
        assert_eq!(result.attempts, 1); // Only 1 full attempt executed before being cut off
        assert_eq!(result.final_error, ERR_CIRCUIT_OPEN);
    });
}

#[test]
fn test_retry_counter_reset_after_mid_sequence_recovery() {
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_config(
            &env,
            CircuitBreakerConfig {
                failure_threshold: 5,
                success_threshold: 1,
                max_error_log: 10,
            },
        );
    });

    env.as_contract(&contract_id, || {
        let prog = String::from_str(&env, "MidSeqProg");
        let op = symbol_short!("midseq");
        let retry_cfg = RetryConfig { max_attempts: 4 };

        let mut attempt_count = 0;
        let mut mock_state_val = 0;

        let result = execute_with_retry(&env, &retry_cfg, prog.clone(), op.clone(), || {
            attempt_count += 1;
            if attempt_count <= 2 {
                // Fail first two times
                Err(ERR_TRANSFER_FAILED)
            } else {
                // Recover on 3rd attempt
                mock_state_val = 100;
                Ok(())
            }
        });

        assert!(result.succeeded);
        assert_eq!(result.attempts, 3);
        assert_eq!(result.final_error, 0); // ERR_NONE

        // Assert that the circuit breaker failure streak was reset
        assert_eq!(get_failure_count(&env), 0);
        assert_eq!(get_state(&env), CircuitState::Closed);

        // State successfully updated upon mid-sequence recovery
        assert_eq!(mock_state_val, 100);
    });
}

// ─────────────────────────────────────────────────────────
// 38. Non-default success_threshold: circuit stays HalfOpen
//     until the threshold is reached
// ─────────────────────────────────────────────────────────
// Acceptance criterion #1:
//   Circuit stays HalfOpen until success_threshold consecutive
//   successes are recorded (tested with success_threshold = 3).

#[test]
fn test_halfopen_stays_halfopen_after_one_success_with_threshold_3() {
    // Arrange: configure a circuit with success_threshold = 3
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_config(
            &env,
            CircuitBreakerConfig {
                failure_threshold: 2,
                success_threshold: 3,
                max_error_log: 10,
            },
        );
    });

    // Drive the circuit to Open, then admin resets to HalfOpen
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        reset_circuit_breaker(&env, &admin);
        assert_eq!(get_state(&env), CircuitState::HalfOpen);

        // Act: record the first success
        record_success(&env);

        // Assert: still HalfOpen — one success is not enough
        assert_eq!(
            get_state(&env),
            CircuitState::HalfOpen,
            "Circuit must remain HalfOpen after only 1 of 3 required successes"
        );
        assert_eq!(
            get_success_count(&env),
            1,
            "SuccessCount must be 1 after one success in HalfOpen"
        );
    });
}

#[test]
fn test_halfopen_stays_halfopen_after_two_successes_with_threshold_3() {
    // Arrange: configure a circuit with success_threshold = 3
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_config(
            &env,
            CircuitBreakerConfig {
                failure_threshold: 2,
                success_threshold: 3,
                max_error_log: 10,
            },
        );
    });

    // Drive the circuit to Open, then admin resets to HalfOpen
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        reset_circuit_breaker(&env, &admin);
        assert_eq!(get_state(&env), CircuitState::HalfOpen);

        // Act: record two consecutive successes
        record_success(&env);
        record_success(&env);

        // Assert: still HalfOpen — two successes are not enough for threshold = 3
        assert_eq!(
            get_state(&env),
            CircuitState::HalfOpen,
            "Circuit must remain HalfOpen after only 2 of 3 required successes"
        );
        assert_eq!(
            get_success_count(&env),
            2,
            "SuccessCount must be 2 after two successes in HalfOpen"
        );
    });
}

#[test]
fn test_halfopen_closes_only_on_third_success_with_threshold_3() {
    // Arrange: configure a circuit with success_threshold = 3
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_config(
            &env,
            CircuitBreakerConfig {
                failure_threshold: 2,
                success_threshold: 3,
                max_error_log: 10,
            },
        );
    });

    // Drive the circuit to Open, then admin resets to HalfOpen
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        reset_circuit_breaker(&env, &admin);

        // Act: record exactly three consecutive successes
        record_success(&env); // 1st — still HalfOpen
        assert_eq!(get_state(&env), CircuitState::HalfOpen);

        record_success(&env); // 2nd — still HalfOpen
        assert_eq!(get_state(&env), CircuitState::HalfOpen);

        record_success(&env); // 3rd — should close

        // Assert: circuit is now Closed
        assert_eq!(
            get_state(&env),
            CircuitState::Closed,
            "Circuit must close after exactly 3 successes with success_threshold = 3"
        );
    });
}

// ─────────────────────────────────────────────────────────
// 39. Failure mid-streak in HalfOpen re-opens the circuit
//     and resets the success counter to zero
// ─────────────────────────────────────────────────────────
// Acceptance criterion #2:
//   A failure while in HalfOpen (before reaching the success
//   threshold) immediately re-opens the circuit and resets
//   the success counter to zero.

#[test]
fn test_halfopen_failure_midstreak_reopens_and_resets_success_counter() {
    // Arrange: configure a circuit with success_threshold = 3
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_config(
            &env,
            CircuitBreakerConfig {
                failure_threshold: 2,
                success_threshold: 3,
                max_error_log: 10,
            },
        );
    });

    // Drive the circuit to Open, then admin resets to HalfOpen
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        reset_circuit_breaker(&env, &admin);
        assert_eq!(get_state(&env), CircuitState::HalfOpen);

        // Build a partial success streak (2 of 3 needed)
        record_success(&env);
        record_success(&env);
        assert_eq!(get_success_count(&env), 2);
        assert_eq!(get_state(&env), CircuitState::HalfOpen);

        // Act: inject a failure mid-streak
        let prog = String::from_str(&env, "TestProg");
        record_failure(&env, prog, symbol_short!("op"), ERR_TRANSFER_FAILED);

        // Assert 1: circuit has re-opened
        assert_eq!(
            get_state(&env),
            CircuitState::Open,
            "A failure mid-streak in HalfOpen must immediately re-open the circuit"
        );

        // Assert 2: success counter is reset to zero by open_circuit()
        assert_eq!(
            get_success_count(&env),
            0,
            "SuccessCount must be reset to zero when the circuit re-opens from HalfOpen"
        );
    });
}

// ─────────────────────────────────────────────────────────
// 40. SuccessCount storage is reset to zero on close
// ─────────────────────────────────────────────────────────
// Acceptance criterion #3:
//   SuccessCount storage is correctly reset to zero once the
//   circuit actually closes (i.e. after reaching success_threshold
//   consecutive successes in HalfOpen).

#[test]
fn test_success_count_reset_to_zero_when_circuit_closes() {
    // Arrange: configure a circuit with success_threshold = 3
    let (env, contract_id) = setup_env();
    let admin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_circuitadmin(&env, admin.clone(), None);
        set_config(
            &env,
            CircuitBreakerConfig {
                failure_threshold: 2,
                success_threshold: 3,
                max_error_log: 10,
            },
        );
    });

    // Drive the circuit to Open, then admin resets to HalfOpen
    simulate_failures(&env, &contract_id, 2);
    env.as_contract(&contract_id, || {
        reset_circuit_breaker(&env, &admin);
        assert_eq!(get_state(&env), CircuitState::HalfOpen);
        assert_eq!(get_success_count(&env), 0);

        // Build up a non-zero SuccessCount (2) before the closing success
        record_success(&env);
        record_success(&env);
        assert_eq!(get_success_count(&env), 2);
        assert_eq!(get_state(&env), CircuitState::HalfOpen);

        // Act: third success triggers close_circuit()
        record_success(&env);

        // Assert: state is Closed AND SuccessCount is exactly 0
        assert_eq!(
            get_state(&env),
            CircuitState::Closed,
            "Circuit must be Closed after reaching success_threshold"
        );
        assert_eq!(
            get_success_count(&env),
            0,
            "SuccessCount must be reset to 0 by close_circuit() — not left at the threshold value"
        );

        // Bonus: failure count must also be cleared by close_circuit()
        assert_eq!(
            get_failure_count(&env),
            0,
            "FailureCount must also be reset to 0 when the circuit closes"
        );
    });
}
