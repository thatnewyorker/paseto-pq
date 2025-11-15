use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use paseto_pq::{Claims, KeyPair, PasetoPQ};
use rand::rng;
use time::{Duration, OffsetDateTime};

fn keypair_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("keypair_generation");

    group.bench_function("ml_dsa_65_keygen", |b| {
        b.iter(|| {
            let mut rng = rng();
            black_box(KeyPair::generate(&mut rng))
        })
    });

    group.finish();
}

fn token_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_signing");

    let mut rng = rng();
    let keypair = KeyPair::generate(&mut rng);

    // Create claims of varying complexity
    let simple_claims = {
        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims.set_issuer("conflux-auth").unwrap();
        claims.set_audience("conflux-network").unwrap();
        claims
    };

    let complex_claims = {
        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims.set_issuer("conflux-auth").unwrap();
        claims.set_audience("conflux-network").unwrap();
        claims.set_jti("unique-token-id-123456789").unwrap();
        claims.set_not_before(OffsetDateTime::now_utc()).unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();
        claims.set_issued_at(OffsetDateTime::now_utc()).unwrap();
        claims.set_kid("key-id-123").unwrap();

        // Add custom claims
        claims.add_custom("tenant_id", "org_abc123456789").unwrap();
        claims
            .add_custom("roles", &["user", "admin", "reader", "writer"])
            .unwrap();
        claims
            .add_custom(
                "scopes",
                &[
                    "read:messages",
                    "write:messages",
                    "admin:users",
                    "manage:keys",
                ],
            )
            .unwrap();
        claims
            .add_custom(
                "permissions",
                &[
                    "chat.send",
                    "chat.receive",
                    "files.upload",
                    "files.download",
                    "admin.users",
                    "admin.keys",
                    "admin.config",
                ],
            )
            .unwrap();
        claims
            .add_custom(
                "metadata",
                &serde_json::json!({
                    "client_version": "1.0.0",
                    "platform": "linux",
                    "features": ["pq-crypto", "e2ee", "forward-secrecy"]
                }),
            )
            .unwrap();

        claims
    };

    group.bench_function("simple_claims", |b| {
        b.iter(|| black_box(PasetoPQ::sign(&keypair.signing_key, &simple_claims).unwrap()))
    });

    group.bench_function("complex_claims", |b| {
        b.iter(|| black_box(PasetoPQ::sign(&keypair.signing_key, &complex_claims).unwrap()))
    });

    group.finish();
}

fn token_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_verification");

    let mut rng = rng();
    let keypair = KeyPair::generate(&mut rng);

    // Pre-generate tokens for verification
    let simple_claims = {
        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims.set_issuer("conflux-auth").unwrap();
        claims.set_audience("conflux-network").unwrap();
        claims
    };

    let complex_claims = {
        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims.set_issuer("conflux-auth").unwrap();
        claims.set_audience("conflux-network").unwrap();
        claims.set_jti("unique-token-id-123456789").unwrap();
        claims.set_not_before(OffsetDateTime::now_utc()).unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();
        claims.set_issued_at(OffsetDateTime::now_utc()).unwrap();
        claims.set_kid("key-id-123").unwrap();

        claims.add_custom("tenant_id", "org_abc123456789").unwrap();
        claims
            .add_custom("roles", &["user", "admin", "reader", "writer"])
            .unwrap();
        claims
            .add_custom(
                "scopes",
                &[
                    "read:messages",
                    "write:messages",
                    "admin:users",
                    "manage:keys",
                ],
            )
            .unwrap();

        claims
    };

    let simple_token = PasetoPQ::sign(&keypair.signing_key, &simple_claims).unwrap();
    let complex_token = PasetoPQ::sign(&keypair.signing_key, &complex_claims).unwrap();

    group.bench_function("simple_token", |b| {
        b.iter(|| black_box(PasetoPQ::verify(&keypair.verifying_key, &simple_token).unwrap()))
    });

    group.bench_function("complex_token", |b| {
        b.iter(|| black_box(PasetoPQ::verify(&keypair.verifying_key, &complex_token).unwrap()))
    });

    group.bench_function("with_audience_validation", |b| {
        b.iter(|| {
            black_box(
                PasetoPQ::verify_with_options(
                    &keypair.verifying_key,
                    &simple_token,
                    Some("conflux-network"),
                    Some("conflux-auth"),
                    Duration::seconds(30),
                )
                .unwrap(),
            )
        })
    });

    group.finish();
}

fn token_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_sizes");
    group.throughput(Throughput::Bytes(1));

    let mut rng = rng();
    let keypair = KeyPair::generate(&mut rng);

    // Test tokens with different payload sizes
    let payload_sizes = [100, 500, 1000, 5000, 10000];

    for size in payload_sizes.iter() {
        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims.set_issuer("conflux-auth").unwrap();
        claims.set_audience("conflux-network").unwrap();

        // Add a large custom field to reach the target size
        let large_data = "x".repeat(*size);
        claims.add_custom("large_field", &large_data).unwrap();

        let token = PasetoPQ::sign(&keypair.signing_key, &claims).unwrap();

        group.throughput(Throughput::Bytes(token.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("verify_by_size", size),
            &token,
            |b, token| {
                b.iter(|| black_box(PasetoPQ::verify(&keypair.verifying_key, token).unwrap()))
            },
        );
    }

    group.finish();
}

fn concurrent_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_operations");

    let mut rng = rng();
    let keypair = KeyPair::generate(&mut rng);

    let claims = {
        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims.set_issuer("my-service").unwrap();
        claims.set_audience("api.example.com").unwrap();
        claims.add_custom("tenant_id", "org_abc123").unwrap();
        claims
    };

    let token = PasetoPQ::sign(&keypair.signing_key, &claims).unwrap();

    // Simulate concurrent signing
    group.bench_function("parallel_signing_4_threads", |b| {
        use std::sync::Arc;
        use std::thread;

        let keypair = Arc::new(keypair.clone());
        let claims = Arc::new(claims.clone());

        b.iter(|| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let keypair = Arc::clone(&keypair);
                    let claims = Arc::clone(&claims);

                    thread::spawn(move || PasetoPQ::sign(&keypair.signing_key, &claims).unwrap())
                })
                .collect();

            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

            black_box(results)
        })
    });

    // Simulate concurrent verification
    group.bench_function("parallel_verification_4_threads", |b| {
        use std::sync::Arc;
        use std::thread;

        let keypair = Arc::new(keypair.clone());
        let token = Arc::new(token.clone());

        b.iter(|| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let keypair = Arc::clone(&keypair);
                    let token = Arc::clone(&token);

                    thread::spawn(move || PasetoPQ::verify(&keypair.verifying_key, &token).unwrap())
                })
                .collect();

            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

            black_box(results)
        })
    });

    group.finish();
}

fn key_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_serialization");

    let mut rng = rng();
    let keypair = KeyPair::generate(&mut rng);

    group.bench_function("signing_key_to_bytes", |b| {
        b.iter(|| black_box(keypair.signing_key_to_bytes()))
    });

    group.bench_function("verifying_key_to_bytes", |b| {
        b.iter(|| black_box(keypair.verifying_key_to_bytes()))
    });

    let signing_bytes = keypair.signing_key_to_bytes();
    let verifying_bytes = keypair.verifying_key_to_bytes();

    group.bench_function("signing_key_from_bytes", |b| {
        b.iter(|| black_box(KeyPair::signing_key_from_bytes(&signing_bytes).unwrap()))
    });

    group.bench_function("verifying_key_from_bytes", |b| {
        b.iter(|| black_box(KeyPair::verifying_key_from_bytes(&verifying_bytes).unwrap()))
    });

    group.finish();
}

fn memory_usage_simulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage");

    // Simulate high-frequency token operations (like a busy gateway)
    group.bench_function("high_frequency_sign_verify_cycle", |b| {
        b.iter(|| {
            let mut rng = rng();
            let keypair = KeyPair::generate(&mut rng);

            // Create 100 tokens rapidly (simulating burst traffic)
            let tokens: Vec<_> = (0..100)
                .map(|i| {
                    let mut claims = Claims::new();
                    claims.set_subject(&format!("user{}", i)).unwrap();
                    claims.set_issuer("my-service").unwrap();
                    claims.set_audience("api.example.com").unwrap();
                    claims.set_jti(&format!("token-{}", i)).unwrap();

                    PasetoPQ::sign(&keypair.signing_key, &claims).unwrap()
                })
                .collect();

            // Verify all tokens
            let verified: Vec<_> = tokens
                .iter()
                .map(|token| PasetoPQ::verify(&keypair.verifying_key, token).unwrap())
                .collect();

            black_box(verified)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    keypair_generation,
    token_signing,
    token_verification,
    token_sizes,
    concurrent_operations,
    key_serialization,
    memory_usage_simulation
);
criterion_main!(benches);
