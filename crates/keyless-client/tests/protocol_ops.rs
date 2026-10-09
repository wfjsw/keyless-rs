//! Rust client against Rust server: every opcode and failure mode.

mod common;

use std::time::Duration;

use aws_lc_rs::{digest, signature};
use common::{client, start_server, Keys, Pki};
use futures_util::future::join_all;
use keyless_client::ClientError;
use keyless_protocol::{ski_from_spki, ErrorCode, Op, Operation, Ski};
use keyless_server::ServerConfig;
use rcgen::{KeyPair, PublicKeyData};

const MSG: &[u8] = b"keyless handshake transcript";

fn sign_op(kp: &KeyPair, opcode: Op, payload: Vec<u8>) -> Operation {
    Operation {
        opcode,
        payload,
        ski: Some(ski_from_spki(&kp.subject_public_key_info()).unwrap()),
        ..Default::default()
    }
}

fn hashed(alg: &'static digest::Algorithm) -> Vec<u8> {
    digest::digest(alg, MSG).as_ref().to_vec()
}

#[tokio::test(flavor = "multi_thread")]
async fn signatures_verify_for_every_key_type() {
    let pki = Pki::new();
    let keys = Keys::new();
    let addr = start_server(&pki, keys.keystore.clone(), ServerConfig::default()).await;
    let client = client(&pki, addr);

    assert_eq!(client.ping(b"hello").await.unwrap(), b"hello");

    type Case = (Op, Option<&'static digest::Algorithm>, &'static dyn signature::VerificationAlgorithm);
    let cases: [(&KeyPair, Vec<Case>); 5] = [
        (&keys.rsa, vec![
            (Op::RSA_SIGN_SHA256, Some(&digest::SHA256), &signature::RSA_PKCS1_2048_8192_SHA256),
            (Op::RSA_SIGN_SHA384, Some(&digest::SHA384), &signature::RSA_PKCS1_2048_8192_SHA384),
            (Op::RSA_SIGN_SHA512, Some(&digest::SHA512), &signature::RSA_PKCS1_2048_8192_SHA512),
            (Op::RSA_PSS_SIGN_SHA256, Some(&digest::SHA256), &signature::RSA_PSS_2048_8192_SHA256),
            (Op::RSA_PSS_SIGN_SHA384, Some(&digest::SHA384), &signature::RSA_PSS_2048_8192_SHA384),
            (Op::RSA_PSS_SIGN_SHA512, Some(&digest::SHA512), &signature::RSA_PSS_2048_8192_SHA512),
        ]),
        (&keys.p256, vec![(Op::ECDSA_SIGN_SHA256, Some(&digest::SHA256), &signature::ECDSA_P256_SHA256_ASN1)]),
        (&keys.p384, vec![(Op::ECDSA_SIGN_SHA384, Some(&digest::SHA384), &signature::ECDSA_P384_SHA384_ASN1)]),
        (&keys.p521, vec![
            (Op::ECDSA_SIGN_SHA512, Some(&digest::SHA512), &signature::ECDSA_P521_SHA512_ASN1),
            (Op::ECDSA_SIGN_SHA384, Some(&digest::SHA384), &signature::ECDSA_P521_SHA384_ASN1),
            (Op::ECDSA_SIGN_SHA256, Some(&digest::SHA256), &signature::ECDSA_P521_SHA256_ASN1),
        ]),
        (&keys.ed25519, vec![(Op::ED25519_SIGN, None, &signature::ED25519)]),
    ];

    for (kp, ops) in cases {
        for (opcode, hash, verify_alg) in ops {
            let payload = hash.map_or(MSG.to_vec(), hashed);
            let sig = client.execute(sign_op(kp, opcode, payload)).await.unwrap();
            signature::UnparsedPublicKey::new(verify_alg, kp.public_key_raw())
                .verify(MSG, &sig)
                .unwrap_or_else(|_| panic!("{opcode} signature did not verify"));
        }
    }

}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_operations_are_rejected_as_bad_opcode() {
    let pki = Pki::new();
    let keys = Keys::new();
    let addr = start_server(&pki, keys.keystore.clone(), ServerConfig::default()).await;
    let client = client(&pki, addr);

    // Deliberate deviation from gokeyless: nothing TLS 1.2+/rustls negotiates,
    // and not expressible with the safe aws-lc-rs API.
    for (kp, opcode, len) in [
        (&keys.rsa, Op::RSA_SIGN_MD5SHA1, 36),
        (&keys.rsa, Op::RSA_SIGN_SHA1, 20),
        (&keys.rsa, Op::RSA_SIGN_SHA224, 28),
        (&keys.p256, Op::ECDSA_SIGN_MD5SHA1, 36),
        (&keys.p256, Op::ECDSA_SIGN_SHA1, 20),
        (&keys.p256, Op::ECDSA_SIGN_SHA384, 48), // hash not matching the curve
        (&keys.p384, Op::ECDSA_SIGN_SHA256, 32),
        (&keys.rsa, Op::RSA_DECRYPT, 256),
    ] {
        match client.execute(sign_op(kp, opcode, vec![0x5A; len])).await {
            Err(ClientError::Remote(ErrorCode::BAD_OPCODE)) => {}
            other => panic!("{opcode}: expected ErrBadOpcode, got {other:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn errors_map_to_gokeyless_codes() {
    let pki = Pki::new();
    let keys = Keys::new();
    let addr = start_server(&pki, keys.keystore.clone(), ServerConfig::default()).await;
    let client = client(&pki, addr);
    let digest = hashed(&digest::SHA256);

    let remote_error = |r: Result<Vec<u8>, ClientError>| match r {
        Err(ClientError::Remote(code)) => code,
        other => panic!("expected remote error, got {other:?}"),
    };

    let mut unknown = sign_op(&keys.rsa, Op::RSA_SIGN_SHA256, digest.clone());
    unknown.ski = Some(Ski([7; 20]));
    assert_eq!(remote_error(client.execute(unknown).await), ErrorCode::KEY_NOT_FOUND);

    let mut no_ski = sign_op(&keys.rsa, Op::RSA_SIGN_SHA256, digest.clone());
    no_ski.ski = None;
    assert_eq!(remote_error(client.execute(no_ski).await), ErrorCode::KEY_NOT_FOUND);

    let wrong_family = sign_op(&keys.rsa, Op::ECDSA_SIGN_SHA256, digest.clone());
    assert_eq!(remote_error(client.execute(wrong_family).await), ErrorCode::CRYPTO);

    let wrong_length = sign_op(&keys.p256, Op::ECDSA_SIGN_SHA384, digest.clone());
    assert_eq!(remote_error(client.execute(wrong_length).await), ErrorCode::CRYPTO);


    for (opcode, code) in [
        (Op::RPC, ErrorCode::BAD_OPCODE),
        (Op(0x99), ErrorCode::BAD_OPCODE),
        (Op::CUSTOM, ErrorCode::BAD_OPCODE),
        (Op::SEAL, ErrorCode::INTERNAL),
        (Op::RESPONSE, ErrorCode::UNEXPECTED_OPCODE),
    ] {
        let resp = client.do_operation(Operation::new(opcode, vec![1])).await.unwrap();
        assert_eq!(resp.error_code(), Some(code), "{opcode}");
    }

    // The connection survives all of the above.
    assert_eq!(client.ping(b"still alive").await.unwrap(), b"still alive");
}

#[tokio::test(flavor = "multi_thread")]
async fn many_concurrent_requests_are_multiplexed() {
    let pki = Pki::new();
    let keys = Keys::new();
    let addr = start_server(&pki, keys.keystore.clone(), ServerConfig::default()).await;
    let client = client(&pki, addr);

    let digest = hashed(&digest::SHA256);
    let requests = (0..500).map(|i| {
        let kp = if i % 2 == 0 { &keys.p256 } else { &keys.rsa };
        let op = if i % 2 == 0 { Op::ECDSA_SIGN_SHA256 } else { Op::RSA_PSS_SIGN_SHA256 };
        client.execute(sign_op(kp, op, digest.clone()))
    });
    let results = join_all(requests).await;
    for (i, sig) in results.into_iter().enumerate() {
        let sig = sig.unwrap();
        let (alg, kp): (&dyn signature::VerificationAlgorithm, _) = if i % 2 == 0 {
            (&signature::ECDSA_P256_SHA256_ASN1, &keys.p256)
        } else {
            (&signature::RSA_PSS_2048_8192_SHA256, &keys.rsa)
        };
        signature::UnparsedPublicKey::new(alg, kp.public_key_raw()).verify(MSG, &sig).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn client_reconnects_after_server_idle_timeout() {
    let pki = Pki::new();
    let keys = Keys::new();
    let config = ServerConfig { idle_timeout: Duration::from_millis(200), ..ServerConfig::default() };
    let addr = start_server(&pki, keys.keystore.clone(), config).await;
    let client = client(&pki, addr);

    assert_eq!(client.ping(b"1").await.unwrap(), b"1");
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(client.ping(b"2").await.unwrap(), b"2");
}

#[tokio::test(flavor = "multi_thread")]
async fn untrusted_client_certificate_is_rejected() {
    let pki = Pki::new();
    let keys = Keys::new();
    let addr = start_server(&pki, keys.keystore.clone(), ServerConfig::default()).await;

    // Same server CA, but a client identity from an unrelated CA.
    let rogue = Pki::new();
    let tls = keyless_client::mtls_client_config(
        [pki.ca_der()],
        vec![rogue.client.0.clone()],
        rogue.client.1.clone_key(),
    )
    .unwrap();
    let config = keyless_client::ClientConfig {
        server_name: Some("localhost".try_into().unwrap()),
        ..Default::default()
    };
    let client = keyless_client::KeylessClient::with_config(addr.to_string(), std::sync::Arc::new(tls), config).unwrap();
    assert!(client.ping(b"x").await.is_err());
}
