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
            (sec_key!(kSecValueData), CFData::from_buffer(b"x").as_CFType()),
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
        Err(e) => assert_eq!(
            e.code(),
            ERR_SEC_PARAM,
            "unexpected ACL creation error"
        ),
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
