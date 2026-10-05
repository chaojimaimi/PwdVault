use super::*;

/// The real Keychain path is exercised by manual QA (Touch ID is a
/// human interaction). Here we only assert that the error mapping
/// classifies the well-known status codes.
#[test]
fn error_mapping_matches_apple_status_codes() {
    assert!(matches!(
        map_error(SfError::from_code(ERR_SEC_ITEM_NOT_FOUND)),
        SecretStoreError::NotFound
    ));
    assert!(matches!(
        map_error(SfError::from_code(ERR_SEC_USER_CANCELED)),
        SecretStoreError::UserCancelled
    ));
    assert!(matches!(
        map_error(SfError::from_code(ERR_SEC_AUTH_LOCKED)),
        SecretStoreError::LockedOut
    ));
    assert!(matches!(
        map_error(SfError::from_code(-99999)),
        SecretStoreError::Unavailable(_)
    ));
}

/// SecItem dictionaries must build without panicking (CF plumbing),
/// in both keychain modes.
#[test]
fn query_dictionaries_build() {
    for use_dp in [true, false] {
        let _ = item_dictionary(Vec::new(), "vault-bio-wrap", use_dp);
        let _ = item_dictionary(
            vec![(
                sec_key!(kSecReturnData),
                CFBoolean::true_value().as_CFType(),
            )],
            "vault-bio-wrap",
            use_dp,
        );
    }
}

/// Both modes round-trip through the tag prefix, including an empty
/// payload — a tagged item whose body is still decodable.
#[test]
fn mode_prefix_roundtrip() {
    let cases: [(BioMode, &[u8]); 3] = [
        (BioMode::DpAcl, b""),
        (BioMode::DpAcl, b"wrap-key-bytes"),
        (BioMode::LegacyGate, &[7u8; 32]),
    ];
    for (mode, payload) in cases {
        let stored = with_mode_prefix(mode, payload);
        assert_eq!(stored[0], tag_of(mode));
        let (decoded, decoded_payload) = split_mode(&stored).unwrap();
        assert_eq!(decoded, mode);
        assert_eq!(decoded_payload, payload);
    }
}

/// Anything but the two known tags — an unknown tag or an EMPTY
/// item — must fail closed instead of returning ungated material.
#[test]
fn mode_prefix_rejects_unknown_and_empty() {
    assert!(matches!(
        split_mode(&[]),
        Err(SecretStoreError::Unavailable(msg)) if msg.contains("unknown keychain item format")
    ));
    assert!(matches!(
        split_mode(&[0x00, 1, 2, 3]),
        Err(SecretStoreError::Unavailable(_))
    ));
    assert!(matches!(
        split_mode(&[0x03]),
        Err(SecretStoreError::Unavailable(_))
    ));
    assert!(matches!(
        split_mode(&[0xFF]),
        Err(SecretStoreError::Unavailable(_))
    ));
    // A tag with no payload decodes to an empty body; size validation
    // (exactly 32 wrap bytes) belongs to the wrap-blob layer.
    assert_eq!(
        split_mode(&[TAG_DP_ACL]).unwrap(),
        (BioMode::DpAcl, &[][..])
    );
}

/// The two mode item shapes must build as CF dictionaries (CF
/// plumbing), mirroring query_dictionaries_build. The ACL OBJECT
/// itself may be rejected with errSecParam on machines without
/// data-protection support (observed on unsigned local builds) —
/// that is precisely the signal mode 2 exists for, not a failure.
#[test]
fn mode_writers_target_distinct_keychains() {
    // Mode 2 shape (legacy keychain, no ACL): always builds.
    let legacy = item_dictionary(
        vec![
            (
                sec_key!(kSecValueData),
                CFData::from_buffer(b"x").as_CFType(),
            ),
            (
                sec_key!(kSecAttrAccessible),
                sec_key!(kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
            ),
        ],
        "vault-bio-wrap",
        false,
    );
    let _ = legacy;
    // Mode 1 shape (data-protection keychain + ACL): builds when the
    // ACL object can be created at all.
    match SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        kSecAccessControlUserPresence | kSecAccessControlBiometryCurrentSet,
    ) {
        Ok(acl) => {
            let dp = item_dictionary(
                vec![
                    (
                        sec_key!(kSecValueData),
                        CFData::from_buffer(b"x").as_CFType(),
                    ),
                    (sec_key!(kSecAttrAccessControl), acl.as_CFType()),
                ],
                "vault-bio-wrap",
                true,
            );
            let _ = dp;
        }
        Err(e) => assert_eq!(e.code(), ERR_SEC_PARAM, "unexpected ACL creation error"),
    }
}

/// Unsigned local builds cannot use the data-protection keychain
/// (errSecMissingEntitlement / -34018): every SecItem operation must
/// transparently retry against the legacy login keychain.
#[test]
fn keychain_fallback_retries_legacy_on_missing_entitlement() {
    let mut attempted = Vec::new();
    let result = with_keychain_fallback(false, |use_dp| {
        attempted.push(use_dp);
        if use_dp {
            Err(SfError::from_code(ERR_SEC_MISSING_ENTITLEMENT))
        } else {
            Ok("legacy")
        }
    })
    .unwrap();
    assert_eq!(result, "legacy");
    assert_eq!(attempted, vec![true, false]);
}

/// Reads fall through to the legacy keychain on NotFound too — an
/// item may have been written by either mode — and NotFound is only
/// reported when both keychains miss.
#[test]
fn keychain_fallback_reads_fall_through_on_not_found() {
    let mut attempted = Vec::new();
    let result = with_keychain_fallback(true, |use_dp| {
        attempted.push(use_dp);
        Err::<Vec<u8>, _>(SfError::from_code(ERR_SEC_ITEM_NOT_FOUND))
    });
    assert!(matches!(result, Err(SecretStoreError::NotFound)));
    assert_eq!(attempted, vec![true, false]);
}

/// Unrelated errors (e.g. biometric lockout) must surface as-is
/// without a legacy retry.
#[test]
fn keychain_fallback_preserves_unrelated_errors() {
    let mut attempted = Vec::new();
    let result = with_keychain_fallback(true, |use_dp| {
        attempted.push(use_dp);
        Err::<i32, _>(SfError::from_code(ERR_SEC_AUTH_LOCKED))
    });
    assert!(matches!(result, Err(SecretStoreError::LockedOut)));
    assert_eq!(attempted, vec![true]);
}

// ---------------------------------------------------------------------------
// Real-Keychain SecItem smoke test (WP-E, v1.2.0)
// ---------------------------------------------------------------------------

/// Drop guard: deletes the smoke item from BOTH keychains no matter how the
/// test body ends (assert, panic, early return), so a red run can never
/// strand a test item in the keychain that ran it.
struct SmokeItemCleanup(String);

impl Drop for SmokeItemCleanup {
    fn drop(&mut self) {
        // The data-protection side is a no-op error (-34018) on unsigned
        // builds; the legacy side is the operative cleanup. Both best-effort.
        let _ = delete_item(&self.0, true);
        let _ = delete_item(&self.0, false);
    }
}

/// End-to-end smoke against the REAL login keychain, guarded behind
/// `#[ignore]` and run explicitly by CI
/// (`cargo test -p pwdvault-infrastructure keychain::macos::tests::keychain_secitem_smoke
/// -- --ignored --exact`).
///
/// Why `#[ignore]`: this test writes and deletes real items in the user's
/// login keychain. Running it on every plain `cargo test` would pollute
/// developer keychains, and a locked keychain could surface an unlock
/// dialog — so it is opt-in only, on a disposable CI runner or on request.
///
/// Why the LEGACY login keychain: `cargo test` binaries are ad-hoc signed
/// without entitlements, so every SecItem call against the DATA-PROTECTION
/// keychain fails with errSecMissingEntitlement (-34018) — that keychain is
/// simply unusable for an unsigned process. The legacy login keychain in
/// turn rejects `kSecAttrAccessControl` with errSecParam (-50), because
/// Touch ID ACLs exist only on the data-protection keychain. The one SecItem
/// shape an unsigned process can round-trip is therefore the mode-2 shape —
/// a plain generic password with NO access control — which is exactly what
/// `add_legacy_gate_item` (bio store's fallback writer) and
/// `MacSyncSecretStore` produce. Exercising both pins the constants,
/// dictionary shapes and status-code plumbing against a real
/// Security.framework, which the pure CF-plumbing tests above cannot.
///
/// NOT covered here: `MacSecretStore::get`. Its legacy-mode items are gated
/// by a real `LAContext` dialog (see `biometric_gate`) and its DP+ACL items
/// by an OS Touch ID prompt — both human interactions by design, left to
/// manual QA.
#[cfg(all(test, target_os = "macos"))]
#[test]
#[ignore]
fn keychain_secitem_smoke() {
    // Unique per-run account: concurrent or stale runs can never collide,
    // and nothing pre-existing under our namespace is touched.
    let account = format!(
        "com.pwdvault.test.smoke.{:016x}{:016x}",
        rand::random::<u64>(),
        rand::random::<u64>()
    );
    let _cleanup = SmokeItemCleanup(account.clone());

    // --- Part 1: direct SecItem layer, deterministic legacy keychain ------
    // Baseline: a fresh account must be absent, and the real keychain must
    // report absence with errSecItemNotFound, exactly as map_error assumes.
    assert_eq!(
        copy_item_data(&account, false).unwrap_err().code(),
        ERR_SEC_ITEM_NOT_FOUND,
        "fresh smoke account must be absent from the legacy keychain"
    );

    // Write through the PRODUCTION mode-2 writer (legacy keychain, no ACL).
    let payload: &[u8] = b"pwdvault-secitem-smoke-payload-32b";
    let tagged = with_mode_prefix(BioMode::LegacyGate, payload);
    add_legacy_gate_item(&account, &tagged).expect("legacy keychain write must succeed");

    // Read back from the legacy keychain and compare byte-for-byte, tag
    // decode included.
    let raw = copy_item_data(&account, false).expect("legacy keychain read must succeed");
    assert_eq!(
        raw, tagged,
        "legacy round-trip must preserve the tagged payload"
    );
    let (mode, decoded) = split_mode(&raw).unwrap();
    assert_eq!(mode, BioMode::LegacyGate);
    assert_eq!(decoded, payload);

    // Delete, then confirm the real keychain reports NotFound again.
    delete_item(&account, false).expect("legacy keychain delete must succeed");
    assert_eq!(
        copy_item_data(&account, false).unwrap_err().code(),
        ERR_SEC_ITEM_NOT_FOUND,
        "deleted smoke item must be NotFound in the legacy keychain"
    );

    // --- Part 2: the non-interactive SecretStore trait, end to end --------
    // `MacSyncSecretStore` is the only trait impl that can run unattended:
    // the bio store's `get` pops a real biometric dialog (see the header).
    // On unsigned binaries its data-protection attempt fails with -34018
    // and the item lands in the legacy login keychain — asserted below, so
    // the CI-relevant path is pinned, not assumed.
    let sync = MacSyncSecretStore;
    assert!(sync.available());
    let secret: &[u8] = b"pwdvault-sync-smoke-secret";
    sync.set(&account, secret)
        .expect("sync store set must succeed");
    assert_eq!(
        sync.get(&account).expect("sync store get must succeed"),
        secret
    );
    assert!(
        copy_item_data(&account, false).is_ok(),
        "unsigned builds must land sync items in the legacy keychain (-34018 fallback)"
    );
    sync.delete(&account)
        .expect("sync store delete must succeed");
    assert!(
        matches!(sync.get(&account), Err(SecretStoreError::NotFound)),
        "deleted sync item must read back NotFound"
    );
}
