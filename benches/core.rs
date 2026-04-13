//! Criterion benchmarks for the active core benchmark suite.
//! **Owner:** Matthew Wang — Testing & Benchmarking
#[path = "support/common.rs"]
mod common;

use anamorph::anamorphic::decrypt::adecrypt_search;
use anamorph::anamorphic::keygen::akeygen_from_params;
use anamorph::anamorphic::{
    adecrypt, adecrypt_legacy, adecrypt_xor, adecrypt_xor_legacy, aencrypt, aencrypt_legacy,
    aencrypt_xor, aencrypt_xor_legacy, akeygen,
};
use anamorph::ec24::{verify_covert_indicator, MultiUseDoubleKey};
use anamorph::normal::decrypt::{decrypt, decrypt_legacy};
use anamorph::normal::encrypt::{encode_message, encrypt, encrypt_legacy, encrypt_with_randomness};
use anamorph::normal::keygen::{keygen_from_params, PublicKey, SecretKey};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use num_bigint::BigUint;

use common::*;

/// Benchmark PRF-based anamorphic encryption across multiple covert payload sizes
/// Measures: aencrypt(pk, dk, NORMAL_MSG, covert, BENCH_MAC_KEY, BENCH_BLOCK_SIZE)
fn bench_prf_encrypt_sizes(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    pk: &PublicKey,
    dk: &anamorph::anamorphic::DoubleKey,
    sizes: &[usize],
) {
    for &covert_size in sizes {
        let covert = payload(covert_size);
        group.throughput(Throughput::Bytes(covert.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(covert_size), &covert, |b, covert| {
            b.iter(|| {
                    black_box(
                    aencrypt(
                        black_box(pk),
                        black_box(dk),
                        black_box(NORMAL_MSG),
                        black_box(covert),
                        black_box(BENCH_MAC_KEY),
                        black_box(BENCH_BLOCK_SIZE),
                    )
                        .expect("anamorphic PRF encrypt"),
                )
            });
        });
    }
}

/// Benchmark PRF-based anamorphic decryption across multiple covert payload sizes
/// Measures: `adecrypt(sk, dk, &prf_packet, BENCH_MAC_KEY, candidate)`
fn bench_prf_decrypt_sizes(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    pk: &PublicKey,
    sk: &SecretKey,
    dk: &anamorph::anamorphic::DoubleKey,
    sizes: &[usize],
) {
    for &covert_size in sizes {
        let covert = payload(covert_size);
        let prf_ct = aencrypt(pk, dk, NORMAL_MSG, &covert, BENCH_MAC_KEY, BENCH_BLOCK_SIZE)
            .expect("anamorphic PRF fixture");
        group.throughput(Throughput::Bytes(covert.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(covert_size), &covert, |b, candidate| {
            b.iter(|| {
                    black_box(
                    adecrypt(
                        black_box(sk),
                        black_box(dk),
                        black_box(&prf_ct),
                        black_box(BENCH_MAC_KEY),
                        black_box(candidate),
                    )
                        .expect("anamorphic PRF decrypt"),
                )
            });
        });
    }
}

/// Benchmark `adecrypt_search`, which scans a set of candidate covert messages
/// Measures: how search-based covert recovery scales with candidate-set size
fn bench_prf_search_sizes(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    pk: &PublicKey,
    sk: &SecretKey,
    dk: &anamorph::anamorphic::DoubleKey,
    candidate_sizes: &[usize],
) {
    let covert = b"search-target";
    let prf_ct = aencrypt_legacy(pk, dk, NORMAL_MSG, covert).expect("anamorphic PRF search fixture");

    for &candidate_count in candidate_sizes {
        let candidates = search_candidates(covert, candidate_count);
        group.throughput(Throughput::Elements(candidates.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(candidate_count),
            &candidates,
            |b, candidates| {
                b.iter(|| {
                    black_box(
                        adecrypt_search(black_box(sk), black_box(dk), black_box(&prf_ct), black_box(candidates))
                            .expect("anamorphic PRF search"),
                    )
                });
            },
        );
    }
}

/// Benchmark XOR-based anamorphic encryption across multiple covert payload sizes
/// Measures: `aencrypt_xor(pk, dk, NORMAL_MSG, covert, BENCH_MAC_KEY, BENCH_BLOCK_SIZE)`
fn bench_xor_encrypt_sizes(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    pk: &PublicKey,
    dk: &anamorph::anamorphic::DoubleKey,
    sizes: &[usize],
) {
    for &covert_size in sizes {
        let covert = payload(covert_size);
        group.throughput(Throughput::Bytes(covert.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(covert_size), &covert, |b, covert| {
            b.iter(|| {
                    black_box(
                    aencrypt_xor(
                        black_box(pk),
                        black_box(dk),
                        black_box(NORMAL_MSG),
                        black_box(covert),
                        black_box(BENCH_MAC_KEY),
                        black_box(BENCH_BLOCK_SIZE),
                    )
                        .expect("anamorphic XOR encrypt"),
                )
            });
        });
    }
}

/// Benchmark XOR-based anamorphic decryption across multiple covert payload sizes
/// Measures: `adecrypt_xor(sk, dk, &xor_packet, BENCH_MAC_KEY)`
fn bench_xor_decrypt_sizes(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    pk: &PublicKey,
    sk: &SecretKey,
    dk: &anamorph::anamorphic::DoubleKey,
    sizes: &[usize],
) {
    for &covert_size in sizes {
        let covert = payload(covert_size);
        let xor_packet =
            aencrypt_xor(pk, dk, NORMAL_MSG, &covert, BENCH_MAC_KEY, BENCH_BLOCK_SIZE)
                .expect("anamorphic XOR fixture");
        group.throughput(Throughput::Bytes(covert.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(covert_size),
            &xor_packet,
            |b, xor_packet| {
                b.iter(|| {
                    black_box(
                        adecrypt_xor(
                            black_box(sk),
                            black_box(dk),
                            black_box(xor_packet),
                            black_box(BENCH_MAC_KEY),
                        )
                            .expect("anamorphic XOR decrypt"),
                    )
                });
            },
        );
    }
}

/// Benchmark EC24 ratcheted PRF-based encryption across multiple covert sizes
/// Measures: one EC24 ratchet step, one PRF anamorphic encryption with the ratcheted key
fn bench_ec24_prf_encrypt_sizes(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    pk: &PublicKey,
    params: &anamorph::params::GroupParams,
    ec24_seed: &MultiUseDoubleKey,
    sizes: &[usize],
) {
    for &covert_size in sizes {
        let covert = payload(covert_size);
        group.throughput(Throughput::Bytes(covert.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(covert_size), &covert, |b, covert| {
            b.iter_batched(
                || ec24_seed.clone(),
                |mut ratcheted| {
                    ratcheted.ratchet(params);
                    black_box(
                            aencrypt(
                                black_box(pk),
                                black_box(ratcheted.current_key()),
                                black_box(NORMAL_MSG),
                                black_box(covert),
                                black_box(BENCH_MAC_KEY),
                                black_box(BENCH_BLOCK_SIZE),
                            )
                            .expect("EC24 ratcheted PRF encrypt"),
                    )
                },
                BatchSize::SmallInput,
            );
        });
    }
}

/// Benchmark EC24 ratcheted XOR-based encryption across multiple covert sizes
/// Measures: one EC24 ratchet step, one XOR anamorphic encryption with the ratcheted key
fn bench_ec24_xor_encrypt_sizes(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    pk: &PublicKey,
    params: &anamorph::params::GroupParams,
    ec24_seed: &MultiUseDoubleKey,
    sizes: &[usize],
) {
    for &covert_size in sizes {
        let covert = payload(covert_size);
        group.throughput(Throughput::Bytes(covert.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(covert_size), &covert, |b, covert| {
            b.iter_batched(
                || ec24_seed.clone(),
                |mut ratcheted| {
                    ratcheted.ratchet(params);
                    black_box(
                            aencrypt_xor(
                                black_box(pk),
                                black_box(ratcheted.current_key()),
                                black_box(NORMAL_MSG),
                                black_box(covert),
                                black_box(BENCH_MAC_KEY),
                                black_box(BENCH_BLOCK_SIZE),
                            )
                            .expect("EC24 ratcheted XOR encrypt"),
                    )
                },
                BatchSize::SmallInput,
            );
        });
    }
}

/// entry point for the core benchmark suite
/// prepares a reusable benchmark fixture once, then registers all benchmark groups intended for routine local runs:
/// - keygen-from-params decomposition
/// - one-off baselines
/// - robustness controls
/// - XOR step controls and scaling
/// - PRF / XOR / EC24 end-to-end payload curves
fn benchmark_fast_core(c: &mut Criterion) {
    // generate one reusable anamorphic key fixture for the whole suite
    let (pk, sk, dk) = akeygen(PARAM_BITS).expect("akeygen for benchmark");

    // reuse the already-generated group parameters for "from_params" keygen benchmarks so those measurements isolate key derivation cost
    let shared_params = pk.params.clone();

    // pre-encode the normal message once so core-encrypt controls do not include message encoding
    let encoded_normal = encode_message(NORMAL_MSG, &pk.params.p).expect("encode benchmark message");

    // use one deterministic exponent for fixed-randomness controls
    let fixed_exponent = &pk.params.q / BigUint::from(2u32);

    // fixed ciphertext for decrypt-side controls
    let fixed_ct = encrypt_with_randomness(&pk, &encoded_normal, &fixed_exponent)
        .expect("step benchmark ciphertext");

    // fixed sender-side shared secret used by XOR step-level breakdowns
    let shared_encrypt = dk.dk_pub.modpow(&fixed_exponent, &pk.params.p);

    // normal ciphertext fixture for normal decrypt and robustness checks
    let normal_ct = encrypt_legacy(&pk, NORMAL_MSG).expect("normal ciphertext for decrypt benchmark");
    let normal_packet = encrypt(&pk, NORMAL_MSG, BENCH_MAC_KEY, BENCH_BLOCK_SIZE)
        .expect("normal packet for decrypt benchmark");

    // empty-payload PRF fixture for PRF empty baseline and wrong-candidate check
    let prf_empty_ct = aencrypt(&pk, &dk, NORMAL_MSG, &[], BENCH_MAC_KEY, BENCH_BLOCK_SIZE)
        .expect("anamorphic PRF empty fixture");

    // an intentional wrong covert candidate used to measure the reject path
    let prf_wrong_candidate = vec![1u8];

    // empty-payload XOR fixture for XOR empty baseline and EC24 indicator checks
    let xor_empty_packet =
        aencrypt_xor(&pk, &dk, NORMAL_MSG, &[], BENCH_MAC_KEY, BENCH_BLOCK_SIZE)
            .expect("anamorphic XOR empty fixture");

    // seed multi-use double key for EC24 ratchet benchmarks
    let ec24_seed = MultiUseDoubleKey::new(dk.clone());

    // key derivation from existing parameters
    let mut keygen_from_params_group = c.benchmark_group("operation_keygen_from_params_total_cost");
    apply_crypto_group_config(&mut keygen_from_params_group);
    keygen_from_params_group.bench_function("Gen_from_params", |b| {
        b.iter(|| black_box(keygen_from_params(black_box(&shared_params)).expect("normal keygen from params")));
    });
    keygen_from_params_group.bench_function("aGen_from_params", |b| {
        b.iter(|| {
            black_box(akeygen_from_params(black_box(&shared_params)).expect("anamorphic keygen from params"))
        });
    });
    keygen_from_params_group.finish();

    // fixed-cost reference points
    c.bench_function("baseline/normal_encrypt_end_to_end", |b| {
        b.iter(|| {
            black_box(
                encrypt(
                    black_box(&pk),
                    black_box(NORMAL_MSG),
                    black_box(BENCH_MAC_KEY),
                    black_box(BENCH_BLOCK_SIZE),
                )
                .expect("normal encrypt"),
            )
        });
    });
    c.bench_function("baseline/normal_decrypt_end_to_end", |b| {
        b.iter(|| {
            black_box(
                decrypt(black_box(&sk), black_box(&normal_packet), black_box(BENCH_MAC_KEY))
                    .expect("normal decrypt"),
            )
        });
    });

    // PRF-mode fixed overhead with empty covert payload
    c.bench_function("baseline/anamorphic_prf_encrypt_empty_payload", |b| {
        b.iter(|| {
            black_box(
                aencrypt(
                    black_box(&pk),
                    black_box(&dk),
                    black_box(NORMAL_MSG),
                    black_box(&[]),
                    black_box(BENCH_MAC_KEY),
                    black_box(BENCH_BLOCK_SIZE),
                )
                .expect("anamorphic PRF encrypt"),
            )
        });
    });
    c.bench_function("baseline/anamorphic_prf_decrypt_empty_payload", |b| {
        b.iter(|| {
            black_box(
                adecrypt(
                    black_box(&sk),
                    black_box(&dk),
                    black_box(&prf_empty_ct),
                    black_box(BENCH_MAC_KEY),
                    black_box(&[]),
                )
                .expect("anamorphic PRF decrypt"),
            )
        });
    });

    // deterministic core-path normal encrypt control
    c.bench_function("control/same_core_fixed_r_encrypt", |b| {
        b.iter(|| {
            black_box(
                encrypt_with_randomness(black_box(&pk), black_box(&encoded_normal), black_box(&fixed_exponent))
                    .expect("same-core normal encrypt"),
            )
        });
    });
    c.bench_function("baseline/anamorphic_xor_encrypt_empty_payload", |b| {
        b.iter(|| {
            black_box(
                aencrypt_xor(
                    black_box(&pk),
                    black_box(&dk),
                    black_box(NORMAL_MSG),
                    black_box(&[]),
                    black_box(BENCH_MAC_KEY),
                    black_box(BENCH_BLOCK_SIZE),
                )
                    .expect("anamorphic XOR encrypt"),
            )
        });
    });
    c.bench_function("baseline/anamorphic_xor_decrypt_empty_payload", |b| {
        b.iter(|| {
            black_box(
                adecrypt_xor(black_box(&sk), black_box(&dk), black_box(&xor_empty_packet), black_box(BENCH_MAC_KEY))
                .expect("anamorphic XOR decrypt"),
            )
        });
    });
    c.bench_function("ec24/ratchet_once", |b| {
        b.iter_batched(
            || ec24_seed.clone(),
            |mut ratcheted| {
                ratcheted.ratchet(&pk.params);
                black_box(ratcheted)
            },
            BatchSize::SmallInput,
        );
    });
    c.bench_function("ec24/verify_covert_indicator", |b| {
        b.iter(|| {
            black_box(
                verify_covert_indicator(
                    black_box(ec24_seed.current_key()),
                    black_box(&prf_empty_ct),
                    black_box(BENCH_MAC_KEY),
                    black_box(&[]),
                    black_box(&pk.params.p),
                    black_box(&pk.params.q),
                    black_box(&pk.params.g),
                )
                .expect("EC24 indicator"),
            )
        });
    });

    //measure "should reject / should indicate no covert payload" cases
    c.bench_function("robustness/prf_adecrypt_on_normal_ciphertext", |b| {
        b.iter(|| {
            black_box(
                adecrypt_legacy(black_box(&sk), black_box(&dk), black_box(&normal_ct), black_box(&[]))
                    .expect("PRF aDec on normal ciphertext"),
            )
        });
    });
    c.bench_function("robustness/prf_adecrypt_wrong_candidate", |b| {
        b.iter(|| {
            black_box(
                adecrypt(
                    black_box(&sk),
                    black_box(&dk),
                    black_box(&prf_empty_ct),
                    black_box(BENCH_MAC_KEY),
                    black_box(&prf_wrong_candidate),
                )
                .expect("PRF aDec on wrong candidate"),
            )
        });
    });
    c.bench_function("robustness/ec24_indicator_on_normal_ciphertext", |b| {
        b.iter(|| {
            black_box(
                verify_covert_indicator(
                    black_box(ec24_seed.current_key()),
                    black_box(&normal_packet),
                    black_box(BENCH_MAC_KEY),
                    black_box(&[]),
                    black_box(&pk.params.p),
                    black_box(&pk.params.q),
                    black_box(&pk.params.g),
                ),
            )
        });
    });

    // operations should be mostly flat with respect to covert payload size
    let mut xor_step_control_group = c.benchmark_group("xor_step_controls");
    apply_payload_scaling_group_config(&mut xor_step_control_group);
    for &covert_size in &XOR_COVERT_SIZES {
        // visible-message encoding cost
        xor_step_control_group.bench_with_input(BenchmarkId::new("encode_message", covert_size), &covert_size, |b, _| {
            b.iter(|| {
                black_box(encode_message(black_box(NORMAL_MSG), black_box(&pk.params.p)).expect("encode message"))
            });
        });

        // deterministic normal encryption core cost
        xor_step_control_group.bench_with_input(
            BenchmarkId::new("encrypt_with_randomness_core", covert_size),
            &covert_size,
            |b, _| {
                b.iter(|| {
                    black_box(
                        encrypt_with_randomness(
                            black_box(&pk),
                            black_box(&encoded_normal),
                            black_box(&fixed_exponent),
                        )
                        .expect("encrypt with fixed randomness"),
                    )
                });
            },
        );

        // sender-side shared-secret computation cost
        xor_step_control_group.bench_with_input(
            BenchmarkId::new("dh_shared_secret_encrypt_side", covert_size),
            &covert_size,
            |b, _| b.iter(|| black_box(dk.dk_pub.modpow(black_box(&fixed_exponent), black_box(&pk.params.p)))),
        );

        // deterministic normal decryption core cost
        xor_step_control_group.bench_with_input(BenchmarkId::new("decrypt_core", covert_size), &covert_size, |b, _| {
            b.iter(|| {
                black_box(decrypt_legacy(black_box(&sk), black_box(&fixed_ct)).expect("decrypt fixed ciphertext"))
            });
        });

        // receiver-side shared-secret computation cost
        xor_step_control_group.bench_with_input(
            BenchmarkId::new("dh_shared_secret_decrypt_side", covert_size),
            &covert_size,
            |b, _| b.iter(|| black_box(dk.shared_secret(black_box(&fixed_ct.c1), black_box(&sk.params.p)))),
        );
    }
    xor_step_control_group.finish();

    // breakdown of XOR-based encryption steps, scaling with covert payload size
    let mut xor_step_group = c.benchmark_group("xor_step_scaling");
    apply_payload_scaling_group_config(&mut xor_step_group);
    for &covert_size in &XOR_COVERT_SIZES {
        let covert = payload(covert_size);
        let keystream = derive_keystream_for_bench(&shared_encrypt, covert.len(), &pk.params.p);

        // cost of producing a keystream of the requested length
        xor_step_group.throughput(Throughput::Bytes(covert.len() as u64));
        xor_step_group.bench_with_input(BenchmarkId::new("keystream_derivation", covert_size), &covert, |b, covert| {
            b.iter(|| black_box(derive_keystream_for_bench(black_box(&shared_encrypt), black_box(covert.len()), black_box(&pk.params.p))));
        });

        // XOR plus allocation / collection overhead
        xor_step_group.throughput(Throughput::Bytes(covert.len() as u64));
        xor_step_group.bench_with_input(BenchmarkId::new("payload_xor_with_alloc", covert_size), &covert, |b, covert| {
            b.iter(|| {
                black_box(
                    covert
                        .iter()
                        .zip(keystream.iter())
                        .map(|(m, k)| m ^ k)
                        .collect::<Vec<u8>>(),
                )
            });
        });

        // XOR into a preallocated output buffer, closer to raw byte-processing cost
        xor_step_group.throughput(Throughput::Bytes(covert.len() as u64));
        xor_step_group.bench_with_input(BenchmarkId::new("payload_xor_in_place", covert_size), &covert, |b, covert| {
            b.iter_batched(
                || vec![0u8; covert.len()],
                |mut out| {
                    for ((dst, m), k) in out.iter_mut().zip(covert.iter()).zip(keystream.iter()) {
                        *dst = *m ^ *k;
                    }
                    black_box(out)
                },
                BatchSize::SmallInput,
            );
        });

        // full end-to-end encryption cost including XOR step and all fixed overheads
        xor_step_group.throughput(Throughput::Bytes(covert.len() as u64));
        xor_step_group.bench_with_input(
            BenchmarkId::new("anamorphic_xor_encrypt_total", covert_size),
            &covert,
            |b, covert| {
                b.iter(|| {
                    black_box(
                        aencrypt_xor_legacy(black_box(&pk), black_box(&dk), black_box(NORMAL_MSG), black_box(covert))
                            .expect("anamorphic XOR encrypt"),
                    )
                });
            },
        );
        let (ct, sideband) =
            aencrypt_xor_legacy(&pk, &dk, NORMAL_MSG, &covert).expect("anamorphic XOR fixture");

        // full end-to-end decryption cost including XOR step and all fixed overheads
        xor_step_group.throughput(Throughput::Bytes(sideband.len() as u64));
        xor_step_group.bench_with_input(BenchmarkId::new("anamorphic_xor_decrypt_total", covert_size), &covert, |b, _| {
            b.iter(|| {
                black_box(
                    adecrypt_xor_legacy(black_box(&sk), black_box(&dk), black_box(&ct), black_box(&sideband))
                        .expect("anamorphic XOR decrypt"),
                )
            });
        });
    }
    xor_step_group.finish();

    // XOR large-payload scaling breakdown
    let mut xor_step_large_group = c.benchmark_group("xor_step_breakdown_large");
    apply_large_payload_scaling_group_config(&mut xor_step_large_group);
    for &covert_size in &XOR_LARGE_COVERT_SIZES {
        let covert = payload(covert_size);
        let keystream = derive_keystream_for_bench(&shared_encrypt, covert.len(), &pk.params.p);

        xor_step_large_group.throughput(Throughput::Bytes(covert.len() as u64));
        xor_step_large_group.bench_with_input(BenchmarkId::new("keystream_derivation", covert_size), &covert, |b, covert| {
            b.iter(|| black_box(derive_keystream_for_bench(black_box(&shared_encrypt), black_box(covert.len()), black_box(&pk.params.p))));
        });
        xor_step_large_group.throughput(Throughput::Bytes(covert.len() as u64));
        xor_step_large_group.bench_with_input(BenchmarkId::new("payload_xor_with_alloc", covert_size), &covert, |b, covert| {
            b.iter(|| {
                black_box(
                    covert
                        .iter()
                        .zip(keystream.iter())
                        .map(|(m, k)| m ^ k)
                        .collect::<Vec<u8>>(),
                )
            });
        });
        xor_step_large_group.throughput(Throughput::Bytes(covert.len() as u64));
        xor_step_large_group.bench_with_input(BenchmarkId::new("payload_xor_in_place", covert_size), &covert, |b, covert| {
            b.iter_batched(
                || vec![0u8; covert.len()],
                |mut out| {
                    for ((dst, m), k) in out.iter_mut().zip(covert.iter()).zip(keystream.iter()) {
                        *dst = *m ^ *k;
                    }
                    black_box(out)
                },
                BatchSize::SmallInput,
            );
        });
        xor_step_large_group.throughput(Throughput::Bytes(covert.len() as u64));
        xor_step_large_group.bench_with_input(
            BenchmarkId::new("anamorphic_xor_encrypt_total", covert_size),
            &covert,
            |b, covert| {
                b.iter(|| {
                    black_box(
                        aencrypt_xor_legacy(black_box(&pk), black_box(&dk), black_box(NORMAL_MSG), black_box(covert))
                            .expect("anamorphic XOR encrypt"),
                    )
                });
            },
        );
        let (ct, sideband) =
            aencrypt_xor_legacy(&pk, &dk, NORMAL_MSG, &covert).expect("anamorphic XOR fixture");
        xor_step_large_group.throughput(Throughput::Bytes(sideband.len() as u64));
        xor_step_large_group.bench_with_input(BenchmarkId::new("anamorphic_xor_decrypt_total", covert_size), &covert, |b, _| {
            b.iter(|| {
                black_box(
                    adecrypt_xor_legacy(black_box(&sk), black_box(&dk), black_box(&ct), black_box(&sideband))
                        .expect("anamorphic XOR decrypt"),
                )
            });
        });
    }
    xor_step_large_group.finish();

    // end-to-end PRF encrypt/decrypt cost over normal-size and large covert payloads
    let mut prf_group = c.benchmark_group("anamorphic_prf_total_cost");
    apply_payload_scaling_group_config(&mut prf_group);
    bench_prf_encrypt_sizes(&mut prf_group, &pk, &dk, &PRF_COVERT_SIZES);
    prf_group.finish();

    let mut prf_large_group = c.benchmark_group("anamorphic_prf_total_cost_large");
    apply_large_payload_scaling_group_config(&mut prf_large_group);
    bench_prf_encrypt_sizes(&mut prf_large_group, &pk, &dk, &PRF_LARGE_COVERT_SIZES);
    prf_large_group.finish();

    let mut prf_decrypt_group = c.benchmark_group("anamorphic_prf_decrypt_total_cost");
    apply_payload_scaling_group_config(&mut prf_decrypt_group);
    bench_prf_decrypt_sizes(&mut prf_decrypt_group, &pk, &sk, &dk, &PRF_COVERT_SIZES);
    prf_decrypt_group.finish();

    let mut prf_decrypt_large_group = c.benchmark_group("anamorphic_prf_decrypt_total_cost_large");
    apply_large_payload_scaling_group_config(&mut prf_decrypt_large_group);
    bench_prf_decrypt_sizes(&mut prf_decrypt_large_group, &pk, &sk, &dk, &PRF_LARGE_COVERT_SIZES);
    prf_decrypt_large_group.finish();

    let mut prf_search_group = c.benchmark_group("anamorphic_prf_search_total_cost");
    apply_payload_scaling_group_config(&mut prf_search_group);
    bench_prf_search_sizes(&mut prf_search_group, &pk, &sk, &dk, &SEARCH_FAST_SET_SIZES);
    prf_search_group.finish();

    // main XOR curves
    let mut xor_encrypt_group = c.benchmark_group("anamorphic_xor_encrypt_total_cost");
    apply_payload_scaling_group_config(&mut xor_encrypt_group);
    bench_xor_encrypt_sizes(&mut xor_encrypt_group, &pk, &dk, &XOR_COVERT_SIZES);
    xor_encrypt_group.finish();

    let mut xor_encrypt_large_group = c.benchmark_group("anamorphic_xor_encrypt_total_cost_large");
    apply_large_payload_scaling_group_config(&mut xor_encrypt_large_group);
    bench_xor_encrypt_sizes(&mut xor_encrypt_large_group, &pk, &dk, &XOR_LARGE_COVERT_SIZES);
    xor_encrypt_large_group.finish();

    let mut xor_decrypt_group = c.benchmark_group("anamorphic_xor_decrypt_total_cost");
    apply_payload_scaling_group_config(&mut xor_decrypt_group);
    bench_xor_decrypt_sizes(&mut xor_decrypt_group, &pk, &sk, &dk, &XOR_COVERT_SIZES);
    xor_decrypt_group.finish();

    let mut xor_decrypt_large_group = c.benchmark_group("anamorphic_xor_decrypt_total_cost_large");
    apply_large_payload_scaling_group_config(&mut xor_decrypt_large_group);
    bench_xor_decrypt_sizes(&mut xor_decrypt_large_group, &pk, &sk, &dk, &XOR_LARGE_COVERT_SIZES);
    xor_decrypt_large_group.finish();

    // end-to-end ratcheted send-side cost for PRF and XOR modes
    let mut ec24_prf_group = c.benchmark_group("ec24_prf_encrypt_total_cost");
    apply_payload_scaling_group_config(&mut ec24_prf_group);
    bench_ec24_prf_encrypt_sizes(&mut ec24_prf_group, &pk, &pk.params, &ec24_seed, &PRF_COVERT_SIZES);
    ec24_prf_group.finish();

    let mut ec24_prf_large_group = c.benchmark_group("ec24_prf_encrypt_total_cost_large");
    apply_large_payload_scaling_group_config(&mut ec24_prf_large_group);
    bench_ec24_prf_encrypt_sizes(&mut ec24_prf_large_group, &pk, &pk.params, &ec24_seed, &PRF_LARGE_COVERT_SIZES);
    ec24_prf_large_group.finish();

    let mut ec24_xor_group = c.benchmark_group("ec24_xor_encrypt_total_cost");
    apply_payload_scaling_group_config(&mut ec24_xor_group);
    bench_ec24_xor_encrypt_sizes(&mut ec24_xor_group, &pk, &pk.params, &ec24_seed, &XOR_COVERT_SIZES);
    ec24_xor_group.finish();

    let mut ec24_xor_large_group = c.benchmark_group("ec24_xor_encrypt_total_cost_large");
    apply_large_payload_scaling_group_config(&mut ec24_xor_large_group);
    bench_ec24_xor_encrypt_sizes(&mut ec24_xor_large_group, &pk, &pk.params, &ec24_seed, &XOR_LARGE_COVERT_SIZES);
    ec24_xor_large_group.finish();
}

criterion_group!(benches, benchmark_fast_core);
criterion_main!(benches);
