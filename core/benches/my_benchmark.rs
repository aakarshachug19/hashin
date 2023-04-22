use criterion::{black_box, criterion_group, criterion_main, BenchmarkId,BatchSize, Criterion};
use hashassin_core::hash_input;
use md5::Md5;
use sha2::Sha256;
use sha2::Sha512;
use ripemd::{Ripemd160, Ripemd320};
use blake2::{Blake2b512, Blake2s256};

/// Compare speeds between all hashing algorithms
pub fn bench_iter(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");

    for pw in ["1", "10", "100", "1000", "10000", "100000"] {
        group.bench_with_input(BenchmarkId::new("md5", pw.len()), pw, |b, pw| {
            b.iter(|| hash_input::<Md5>(hashassin_core::HashAlgorithm::Md5, black_box(pw)));
        });

        group.bench_with_input(BenchmarkId::new("sha256", pw.len()), pw, |b, pw| {
            b.iter(|| hash_input::<Sha256>(hashassin_core::HashAlgorithm::Sha2, black_box(pw)));
        });

        group.bench_with_input(BenchmarkId::new("sha512", pw.len()), pw, |b, pw| {
            b.iter(|| hash_input::<Sha512>(hashassin_core::HashAlgorithm::Sha512,black_box(pw)));
        });

        group.bench_with_input(BenchmarkId::new("ripenmd160", pw.len()), pw, |b, pw| {
            b.iter(|| hash_input::<Ripemd160>(hashassin_core::HashAlgorithm::Ripemd160,black_box(pw)));
        });
        
        group.bench_with_input(BenchmarkId::new("ripemd320", pw.len()), pw, |b, pw| {
            b.iter(|| hash_input::<Ripemd320>(hashassin_core::HashAlgorithm::Ripemd320,black_box(pw)));
        });

        group.bench_with_input(BenchmarkId::new("blake2b512", pw.len()), pw, |b, pw| {
            b.iter(|| hash_input::<Blake2b512>(hashassin_core::HashAlgorithm::Blake2b512,black_box(pw)));
        });

        group.bench_with_input(BenchmarkId::new("Blake2s256", pw.len()), pw, |b, pw| {
            b.iter(|| hash_input::<Blake2s256>(hashassin_core::HashAlgorithm::Blake2s256,black_box(pw)));
        });
        
    }

    group.finish();
}


/// Compare speeds between all hashing algorithms
pub fn bench_iter_batched(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_iter_batched");

    for pw in ["1", "10", "100", "1000", "10000", "100000"] {
        group.bench_with_input(BenchmarkId::new("md5", pw.len()), &pw, |b, &pw| {
            b.iter_batched(
                || pw.clone(),
                |pw| {
                    hash_input::<Md5>(hashassin_core::HashAlgorithm::Md5,black_box(pw));
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("sha256", pw.len()), &pw, |b, &pw| {
            b.iter_batched(
                || pw.clone(),
                |pw| {
                    hash_input::<Sha256>(hashassin_core::HashAlgorithm::Sha2,black_box(pw));
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("Sha512", pw.len()), &pw, |b, &pw| {
            b.iter_batched(
                || pw.clone(),
                |pw| {
                    hash_input::<Sha512>(hashassin_core::HashAlgorithm::Sha512,black_box(pw));
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("Ripemd160", pw.len()), &pw, |b, &pw| {
            b.iter_batched(
                || pw.clone(),
                |pw| {
                    hash_input::<Ripemd160>(hashassin_core::HashAlgorithm::Ripemd160,black_box(pw));
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("Ripemd320", pw.len()), &pw, |b, &pw| {
            b.iter_batched(
                || pw.clone(),
                |pw| {
                    hash_input::<Ripemd320>(hashassin_core::HashAlgorithm::Ripemd320,black_box(pw));
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("Blake2b512", pw.len()), &pw, |b, &pw| {
            b.iter_batched(
                || pw.clone(),
                |pw| {
                    hash_input::<Blake2b512>(hashassin_core::HashAlgorithm::Blake2b512,black_box(pw));
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("Blake2s256", pw.len()), &pw, |b, &pw| {
            b.iter_batched(
                || pw.clone(),
                |pw| {
                    hash_input::<Blake2s256>(hashassin_core::HashAlgorithm::Blake2s256,black_box(pw));
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}



criterion_group!(benches, bench_iter_batched,bench_iter);
criterion_main!(benches);
