#[path = "support/common.rs"]
mod common;

use anamorph::anamorphic::akeygen;
use anamorph::params::generate_group_params;
use anamorph::normal::keygen::keygen;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use common::{apply_slow_setup_group_config, PARAM_BITS};

/// entry point for the slow setup benchmark suite
/// isolates the heavyweight setup operations that dominate runtime and are therefore excluded from the core suite:
/// - safe-prime group parameter generation
/// - full normal key generation
/// - full anamorphic key generation
fn benchmark_slow_setup(c: &mut Criterion) {
    // benchmark safe-prime group generation directly
    let mut params_group = c.benchmark_group("operation_params_total_cost");
    apply_slow_setup_group_config(&mut params_group);
    params_group.bench_function("GenerateGroupParams", |b| {
        b.iter(|| black_box(generate_group_params(black_box(PARAM_BITS)).expect("group parameter generation")));
    });
    params_group.finish();

    // benchmark full key generation paths, including fresh parameter generation
    let mut keygen_group = c.benchmark_group("operation_keygen_total_cost");
    apply_slow_setup_group_config(&mut keygen_group);
    keygen_group.bench_function("Gen", |b| {
        b.iter(|| black_box(keygen(black_box(PARAM_BITS)).expect("normal keygen")));
    });
    keygen_group.bench_function("aGen", |b| {
        b.iter(|| black_box(akeygen(black_box(PARAM_BITS)).expect("anamorphic keygen")));
    });
    keygen_group.finish();
}

criterion_group!(benches, benchmark_slow_setup);
criterion_main!(benches);
