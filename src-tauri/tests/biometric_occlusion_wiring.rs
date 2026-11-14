//! v1.8.6 source-contract test for the Touch ID prompt cancel wiring.
//!
//! The v1.8.5 window-event cancel arms were empirically falsified (tao's
//! macOS delegate has no windowDidMiniaturize — the arms' focus-loss
//! premise never fires; the earlier "the app stays active while the prompt
//! is up" reading was itself falsified on-device 2026-11-13: the panel
//! strips the app's active status ~50ms after it appears), so the cancel
//! REQUEST must now come from the AppKit occlusion-state observer in
//! `src/lib.rs`. This test pins the wiring in the lib.rs SOURCE
//! (include_str! — the capability_contract.rs:25 precedent):
//!
//! ① the occlusion observer registration exists, anchored on the
//!    `addObserverForName` CALL SHAPE — never on the notification-name
//!    literal, which lib.rs's own explanatory comment also carries and which
//!    would make the anchor tautological (plan §1 F1.2 warning);
//! ② the cancel request is produced INSIDE the occlusion block (structurally:
//!    the call sits between the block construction and its consumption by the
//!    registration call), behind the macOS cfg gate;
//! ③ the falsified v1.8.5 event-arm forms are GONE, including their rationale
//!    comment block — arm-form-shaped anchors are used deliberately: bare
//!    prose in comments may survive, the `tauri::WindowEvent::` match-arm
//!    shapes and the `is_minimized` cancel-guard may not (its total absence
//!    is intentional — both cancel arms guarded on it and nothing else in
//!    lib.rs queries the minimized flag);
//! ④ the close-to-tray cancel arm survives (F2 keeps it: it fires before the
//!    hide, ahead of the occlusion notification's delivery).
//!
//! The test's own assertion strings live in THIS file while the scanned
//! source lives in lib.rs — no self-collision is possible (the v1.8.4 #18③
//! lesson is why this is a separate integration-test file at all). Three test
//! functions: this one (v1.8.6 occlusion wiring, budget 464 → 465),
//! `resign_active_observer_cancels_pending_prompt` (v1.8.7 resign-active
//! wiring, budget 465 → 466) and `workspace_activation_observer_cancels_
//! pending_prompt` (v1.8.8 workspace wiring, budget 466 → 467).

const LIB_SRC: &str = include_str!("../src/lib.rs");

#[test]
fn occlusion_cancel_wiring_contract() {
    // --- ① + ② registration wired, cancel produced inside the block --------
    // Call-shape anchor (NOT the notification-name literal).
    let registration_call = "addObserverForName_object_queue_usingBlock(";
    let registration = LIB_SRC.find(registration_call).unwrap_or_else(|| {
        panic!(
            "lib.rs must register the occlusion observer via \
                 NSNotificationCenter::{registration_call} — without it the \
                 Touch ID prompt can never be cancelled on minimize/hide"
        )
    });

    // The registration must sit behind the macOS cfg gate: `ns_window()` is a
    // macOS-cfg tauri API and the objc2 stack `compile_error!`s on non-Apple
    // targets — an ungated block breaks the Windows release CI
    // (v1.8.5 R1-P1 lesson).
    assert!(
        LIB_SRC.contains("#[cfg(target_os = \"macos\")]"),
        "the occlusion registration block must be cfg-gated to macOS"
    );

    // The cancel request is produced inside the block: the explicitly typed
    // RcBlock (the annotation makes the &RcBlock -> &DynBlock deref coercion
    // fire, same shape as biometric_gate.rs's reply block) is constructed
    // BEFORE the registration consumes it, and the cancel call must live in
    // that closure body.
    let block_annotation = "RcBlock<dyn Fn(NonNull<NSNotification>)>";
    let block_start = LIB_SRC.find(block_annotation).unwrap_or_else(|| {
        panic!(
            "the occlusion block must be an explicitly typed {block_annotation} \
             (deref coercion watch-point)"
        )
    });
    assert!(
        block_start < registration,
        "the occlusion block must be constructed before its registration call"
    );
    let block_body = &LIB_SRC[block_start..registration];
    assert!(
        block_body.contains("cancel_pending_biometric_prompt"),
        "the occlusion notification block must call \
         cancel_pending_biometric_prompt — the polling cancel loop in \
         infrastructure has no other request producer since v1.8.6"
    );

    // --- ③ falsified v1.8.5 event arms and their rationale swept -----------
    // Anchors are the exact ARM FORMS — `wry #490` was cited only by the
    // deleted rationale block.
    for stale_shape in [
        "WindowEvent::Focused(false)",
        "WindowEvent::Resized",
        "is_minimized",
        "wry #490",
    ] {
        assert!(
            !LIB_SRC.contains(stale_shape),
            "stale v1.8.5 form must stay removed from lib.rs: {stale_shape}"
        );
    }

    // --- ④ the close-to-tray cancel arm survives ---------------------------
    // The cancel call must still sit between the CloseRequested arm and the
    // hide call.
    let arm = LIB_SRC
        .find("WindowEvent::CloseRequested")
        .expect("the CloseRequested cancel arm must remain in lib.rs");
    let hide = LIB_SRC[arm..]
        .find("win.hide()")
        .expect("the CloseRequested arm must hide the window to tray");
    assert!(
        LIB_SRC[arm..arm + hide].contains("cancel_pending_biometric_prompt"),
        "an in-flight Touch ID dialog must still be cancelled before the \
         hide-to-tray (v1.8.5 behavior kept by v1.8.6 F2)"
    );
}

/// v1.8.7: the resign-active observer — the app-level complement to the
/// window-level occlusion observer (Stage Manager's shrunken tile keeps the
/// window "visible" on screen, so occlusion never fires on a plain app
/// switch). The assertions mirror the occlusion contract:
///
/// ⑤ the notification-name literal exists in its QUOTED form, exactly once
///    (lib.rs is forbidden from carrying the full name in comments —
///    "resign-active" prose only — so the quoted literal is a
///    non-tautological registration anchor);
/// ⑥ the registration call shape occurs exactly THREE times, occlusion
///    first in file order (the v1.8.6 first-occurrence anchors in
///    `occlusion_cancel_wiring_contract` must keep pointing at it), the
///    resign registration second, and the v1.8.8 workspace-activation
///    registration third;
/// ⑦ the resign segment — from the name literal to the SECOND registration
///    call (`match_indices().nth(1)`, never a bare find, which would hit the
///    occlusion registration and invert the bounds) — produces the cancel
///    request.
#[test]
fn resign_active_observer_cancels_pending_prompt() {
    // --- ⑤ quoted name literal, exactly once -------------------------------
    let name_literal = "\"NSApplicationDidResignActiveNotification\"";
    assert_eq!(
        LIB_SRC.matches(name_literal).count(),
        1,
        "the resign-active notification must be registered through its \
         quoted string literal exactly once — lib.rs comments may not carry \
         the full name (resign-active prose only), so this anchor cannot be \
         satisfied by prose"
    );

    // --- ⑥ exactly three registration calls, occlusion first ----------------
    let registration_call = "addObserverForName_object_queue_usingBlock(";
    let call_sites: Vec<usize> = LIB_SRC
        .match_indices(registration_call)
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        call_sites.len(),
        3,
        "lib.rs must register exactly three AppKit observers (occlusion + \
         resign-active + workspace activation) through the same call shape"
    );
    assert!(
        call_sites[0] < call_sites[1],
        "file order is pinned: the occlusion registration must stay FIRST so \
         the v1.8.6 first-occurrence anchors keep pointing at it"
    );
    // Identity + order chain (v1.8.7 review fold): `call_sites[0] < call_sites[1]`
    // is vacuously true under `len == 2` (match_indices positions are strictly
    // increasing), so a plain swap of the two observers would pass it. Pin the
    // occlusion registration's IDENTITY via its own quoted name literal —
    // unique in lib.rs in quoted form (prose mentions use backticks) — so the
    // chain "occlusion literal < first registration < second registration"
    // turns an observer swap (and a swap-combined cancel removal, which the
    // count alone cannot see) red.
    let occlusion_literal = "\"NSWindowDidChangeOcclusionStateNotification\"";
    let occlusion_name_at = LIB_SRC
        .find(occlusion_literal)
        .expect("occlusion quoted name literal (unique in lib.rs)");
    assert!(
        occlusion_name_at < call_sites[0],
        "identity + order chain: the occlusion registration is FIRST and the \
         resign registration SECOND — the v1.8.6 first-occurrence anchors \
         depend on this order"
    );

    // --- ⑦ the resign segment produces the cancel request ------------------
    let start = LIB_SRC
        .find(name_literal)
        .expect("resign-active name literal position (asserted present above)");
    let end = call_sites[1];
    assert!(
        start < end,
        "segment bounds must be monotonic — the resign name literal precedes \
         its registration call (second in file order)"
    );
    assert!(
        LIB_SRC[start..end].contains("cancel_pending_biometric_prompt"),
        "the resign-active block must produce the cancel request — the \
         polling cancel loop in infrastructure has no other trigger for \
         app-switch episodes"
    );
}

/// v1.8.8 (F4): the workspace-activation observer — the state-INDEPENDENT
/// companion to the resign-active observer. Scenario A: if the auth panel
/// permanently strips the app's active status at raise time, a later user
/// switch produces NO active→inactive transition, and resign-active can
/// never fire again while the dialog is up. A workspace activation fires
/// whenever ANY other application gains activation, regardless of whether
/// we were still active — both scenarios covered. The assertions:
///
/// ⑧ the workspace notification-name literal exists in its QUOTED form,
///    exactly once (lib.rs is forbidden from carrying the full name in
///    comments — "workspace activation" prose only — so the quoted literal
///    is a non-tautological registration anchor, same discipline as ⑤);
/// ⑨ the workspace segment — from the name literal to the THIRD
///    registration call (`match_indices().nth(2)`, never a bare find, which
///    would hit an earlier registration and invert the bounds) — produces
///    the cancel request;
/// ⑩ that segment also parses the activated application's pid
///    (`processIdentifier` form anchor): without the pid comparison the
///    observer cannot tell a self-activation from a genuine user switch.
#[test]
fn workspace_activation_observer_cancels_pending_prompt() {
    // --- ⑧ quoted name literal, exactly once -------------------------------
    let name_literal = "\"NSWorkspaceDidActivateApplicationNotification\"";
    assert_eq!(
        LIB_SRC.matches(name_literal).count(),
        1,
        "the workspace activation notification must be registered through \
         its quoted string literal exactly once — lib.rs comments may not \
         carry the full name (workspace activation prose only), so this \
         anchor cannot be satisfied by prose"
    );

    // --- ⑨ the workspace segment (literal → third call) cancels ------------
    let registration_call = "addObserverForName_object_queue_usingBlock(";
    let end = LIB_SRC
        .match_indices(registration_call)
        .nth(2)
        .map(|(index, _)| index)
        .expect("the third registration call (workspace activation)");
    let start = LIB_SRC
        .find(name_literal)
        .expect("workspace activation name literal position (asserted above)");
    assert!(
        start < end,
        "segment bounds must be monotonic — the workspace name literal \
         precedes its registration call (third in file order)"
    );
    assert!(
        LIB_SRC[start..end].contains("cancel_pending_biometric_prompt"),
        "the workspace activation block must produce the cancel request — \
         the state-independent signal when resign-active can never fire \
         again (panel-permanently-inactive scenario)"
    );

    // --- ⑩ the segment distinguishes self from others via the pid ----------
    assert!(
        LIB_SRC[start..end].contains("processIdentifier"),
        "the workspace activation block must compare the activated \
         application's pid against our own — without it the observer cannot \
         tell a self-activation from a genuine user switch and would \
         self-cancel every prompt"
    );
}
