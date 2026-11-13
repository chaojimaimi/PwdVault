//! v1.8.6 source-contract test for the Touch ID prompt cancel wiring.
//!
//! The v1.8.5 window-event cancel arms were empirically falsified (the auth
//! dialog steals key status at raise time and tao's macOS delegate has no
//! windowDidMiniaturize), so the cancel REQUEST must now come from the AppKit
//! occlusion-state observer in `src/lib.rs`. This test pins the wiring in the
//! lib.rs SOURCE (include_str! — the capability_contract.rs:25 precedent):
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
//! lesson is why this is a separate integration-test file at all). One test
//! function on purpose: the plan's test budget is exactly +1 (464 → 465).

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
