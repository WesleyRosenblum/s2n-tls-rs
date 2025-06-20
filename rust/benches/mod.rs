// Performance benchmarks for s2n-tls-rs
//
// This module contains performance benchmarks for the s2n-tls-rs implementation.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use s2n_tls_rs::{init, cleanup, Config, Connection, ConnectionMode};
use s2n_tls_rs::crypto::cipher_suites::TLS_AES_128_GCM_SHA256;
use s2n_tls_rs::handshake::NamedGroup;

mod handshake;
mod throughput;

criterion_group!(benches, handshake::bench_handshake, throughput::bench_throughput);
criterion_main!(benches);
