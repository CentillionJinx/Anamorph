#[path = "support/common.rs"]
mod common;

use anamorph::anamorphic::{adecrypt_stream, aencrypt_stream, akeygen};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use common::{
    apply_slow_stream_group_config, payload, BENCH_BLOCK_SIZE, BENCH_MAC_KEY, NORMAL_MSG,
    PARAM_BITS, STREAM_COVERT_SIZES, STREAM_LARGE_COVERT_SIZES,
};

/// Benchmark stream-mode anamorphic encryption across multiple covert lengths
/// Measures: `aencrypt_stream(pk, dk, NORMAL_MSG, covert, BENCH_MAC_KEY, BENCH_BLOCK_SIZE, Some(65536))`
fn bench_stream_encrypt_sizes(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    pk: &anamorph::normal::keygen::PublicKey,
    dk: &anamorph::anamorphic::DoubleKey,
    sizes: &[usize],
) {
    for &covert_size in sizes {
        let covert = payload(covert_size);
        group.throughput(Throughput::Bytes(covert.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(covert_size), &covert, |b, covert| {
            b.iter(|| {
                black_box(
                    aencrypt_stream(
                        black_box(pk),
                        black_box(dk),
                        black_box(NORMAL_MSG),
                        black_box(covert),
                        black_box(BENCH_MAC_KEY),
                        black_box(BENCH_BLOCK_SIZE),
                        black_box(Some(65_536)),
                    )
                    .expect("anamorphic stream encrypt"),
                )
            });
        });
    }
}

/// Benchmark stream-mode anamorphic decryption across multiple covert lengths
/// Measures: `adecrypt_stream(sk, dk, &stream_packets, BENCH_MAC_KEY)`
fn bench_stream_decrypt_sizes(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    pk: &anamorph::normal::keygen::PublicKey,
    sk: &anamorph::normal::keygen::SecretKey,
    dk: &anamorph::anamorphic::DoubleKey,
    sizes: &[usize],
) {
    for &covert_size in sizes {
        let covert = payload(covert_size);
        let stream_cts =
            aencrypt_stream(
                pk,
                dk,
                NORMAL_MSG,
                &covert,
                BENCH_MAC_KEY,
                BENCH_BLOCK_SIZE,
                Some(65_536),
            )
            .expect("anamorphic stream fixture");
        group.throughput(Throughput::Bytes(covert.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(covert_size), &covert, |b, _| {
            b.iter(|| {
                black_box(
                    adecrypt_stream(black_box(sk), black_box(dk), black_box(&stream_cts), black_box(BENCH_MAC_KEY))
                        .expect("anamorphic stream decrypt"),
                )
            });
        });
    }
}

/// entry point for the slow stream benchmark suite
/// measures the rejection-sampling stream construction separately because it
/// is orders of magnitude slower than the single-ciphertext PRF/XOR modes:
/// - routine stream sizes: 1, 4, 16 covert bytes
/// - optional very-slow stream sizes: 64, 256 covert bytes
fn benchmark_slow_stream(c: &mut Criterion) {
    // generate one reusable key fixture for the whole stream suite
    let (pk, sk, dk) = akeygen(PARAM_BITS).expect("akeygen for slow stream benchmark");

    // stream-mode encryption cost for the routine small-size sweep
    let mut encrypt_group = c.benchmark_group("anamorphic_stream_encrypt_total_cost");
    apply_slow_stream_group_config(&mut encrypt_group);
    bench_stream_encrypt_sizes(&mut encrypt_group, &pk, &dk, &STREAM_COVERT_SIZES);
    encrypt_group.finish();

    // stream-mode decryption cost for the routine small-size sweep
    let mut decrypt_group = c.benchmark_group("anamorphic_stream_decrypt_total_cost");
    apply_slow_stream_group_config(&mut decrypt_group);
    bench_stream_decrypt_sizes(&mut decrypt_group, &pk, &sk, &dk, &STREAM_COVERT_SIZES);
    decrypt_group.finish();

    // opt-in very-slow stream cases for deep investigation only
    if std::env::var_os("ANAMORPH_ENABLE_VERY_SLOW_STREAM").is_some() {
        let mut encrypt_large_group = c.benchmark_group("anamorphic_stream_encrypt_total_cost_large");
        apply_slow_stream_group_config(&mut encrypt_large_group);
        bench_stream_encrypt_sizes(&mut encrypt_large_group, &pk, &dk, &STREAM_LARGE_COVERT_SIZES);
        encrypt_large_group.finish();

        let mut decrypt_large_group = c.benchmark_group("anamorphic_stream_decrypt_total_cost_large");
        apply_slow_stream_group_config(&mut decrypt_large_group);
        bench_stream_decrypt_sizes(&mut decrypt_large_group, &pk, &sk, &dk, &STREAM_LARGE_COVERT_SIZES);
        decrypt_large_group.finish();
    }
}

criterion_group!(benches, benchmark_slow_stream);
criterion_main!(benches);
