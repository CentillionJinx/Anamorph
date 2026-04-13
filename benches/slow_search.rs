#[path = "support/common.rs"]
mod common;

use anamorph::anamorphic::decrypt::adecrypt_search;
use anamorph::anamorphic::{aencrypt_legacy, akeygen};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use common::{apply_slow_search_group_config, search_candidates, SEARCH_SLOW_SET_SIZES, NORMAL_MSG, PARAM_BITS};

/// entry point for the slow PRF-search benchmark suite
/// focuses on the larger candidate-set sizes that are useful for deeper
/// robustness analysis but too slow for the default routine benchmark run:
/// - search-based PRF anamorphic recovery with candidate sets 64 and 256
fn benchmark_slow_search(c: &mut Criterion) {
    // generate one reusable key fixture for the whole slow-search suite
    let (pk, sk, dk) = akeygen(PARAM_BITS).expect("akeygen for slow search benchmark");

    // fix one covert target so the search cost varies only with candidate-set size
    let covert = b"search-target";

    // prepare one ciphertext that really contains the chosen target
    let prf_ct = aencrypt_legacy(&pk, &dk, NORMAL_MSG, covert).expect("anamorphic PRF search fixture");

    let mut search_group = c.benchmark_group("anamorphic_prf_search_total_cost_large");
    apply_slow_search_group_config(&mut search_group);

    for &candidate_count in &SEARCH_SLOW_SET_SIZES {
        // build a search set where the true covert target is present once
        let candidates = search_candidates(covert, candidate_count);
        search_group.throughput(Throughput::Elements(candidates.len() as u64));
        search_group.bench_with_input(
            BenchmarkId::from_parameter(candidate_count),
            &candidates,
            |b, candidates| {
                b.iter(|| {
                    black_box(
                        // Measures: adecrypt_search(sk, dk, &prf_ct, candidates)
                        adecrypt_search(black_box(&sk), black_box(&dk), black_box(&prf_ct), black_box(candidates))
                            .expect("anamorphic PRF search"),
                    )
                });
            },
        );
    }

    search_group.finish();
}

criterion_group!(benches, benchmark_slow_search);
criterion_main!(benches);
