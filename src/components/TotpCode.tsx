import { useCallback, useEffect, useRef, useState } from "react";
import { totpCode } from "../api/vault";
import type { TotpCodeResponse } from "../types";
import { isVaultError } from "../utils/errorMessage";
import { copyWithTimeout } from "../utils/clipboard";
import { showToast } from "../utils/toast";
import { CopyIcon } from "./Icons";

interface TotpCodeProps {
	entryId: string;
}

/** Permanent rejection: the entry has no TOTP secret at all. */
function isTotpNotConfigured(error: unknown): boolean {
	return (
		isVaultError(error) &&
		typeof error === "object" &&
		"InvalidInput" in error &&
		error.InvalidInput.code === "TOTP_NOT_CONFIGURED"
	);
}

/** Retry delay (in countdown ticks) after a transient fetch failure. */
const RETRY_TICKS = 5;

/**
 * Live TOTP code for a saved entry (Phase 2 / P3.5): shows the current
 * 6-digit code plus a per-second countdown, re-fetching from the backend
 * when the countdown expires so clock drift re-syncs with the real period.
 * Renders nothing while the entry has no configured secret (the backend
 * answers `TOTP_NOT_CONFIGURED`, which stops polling outright) or cannot be
 * reached (transient failures retry after a short delay) — the entry stays
 * editable either way.
 */
export function TotpCode({ entryId }: TotpCodeProps) {
	const [totp, setTotp] = useState<TotpCodeResponse | null>(null);
	const [secondsRemaining, setSecondsRemaining] = useState(0);
	const [notConfigured, setNotConfigured] = useState(false);
	const fetchingRef = useRef(false);

	const fetchCode = useCallback(async () => {
		if (fetchingRef.current) return;
		fetchingRef.current = true;
		try {
			const next = await totpCode(entryId);
			setTotp(next);
			// Clamp at 1: a reported 0 would re-trigger the expiry effect below
			// in the same tick and spin the fetch into a loop.
			setSecondsRemaining(Math.max(1, next.seconds_remaining));
		} catch (error) {
			setTotp(null);
			if (isTotpNotConfigured(error)) {
				// No secret configured — permanent for this entry: stop polling.
				setNotConfigured(true);
			} else {
				// Vault locked / backend busy — retry after a short delay so the
				// component never wedges at 0; the countdown keeps ticking.
				setSecondsRemaining(RETRY_TICKS);
			}
		} finally {
			fetchingRef.current = false;
		}
	}, [entryId]);

	// Initial fetch on mount / entry change.
	useEffect(() => {
		if (notConfigured) return;
		void fetchCode();
	}, [fetchCode, notConfigured]);

	// Refetch whenever the countdown expires. Kept out of the setState
	// updater above: updater functions must stay pure.
	useEffect(() => {
		if (notConfigured || secondsRemaining > 0) return;
		void fetchCode();
	}, [notConfigured, secondsRemaining, fetchCode]);

	// Pure per-second decrement, floored at 0.
	useEffect(() => {
		if (notConfigured) return;
		const interval = window.setInterval(() => {
			setSecondsRemaining((s) => (s <= 0 ? 0 : s - 1));
		}, 1000);
		return () => window.clearInterval(interval);
	}, [notConfigured]);

	const handleCopy = async () => {
		if (!totp) return;
		await copyWithTimeout(totp.code);
		showToast("TOTP code copied (auto-clears in 30s)");
	};

	if (!totp) return null;

	return (
		<div className="totp-display">
			<span className="totp-code" aria-label="Current TOTP code">
				{totp.code}
			</span>
			<span
				className="totp-timer"
				role="timer"
				aria-label={`Code refreshes in ${secondsRemaining} seconds`}
			>
				{secondsRemaining}s
			</span>
			<button
				type="button"
				className="btn btn-icon"
				onClick={() => void handleCopy()}
				aria-label="Copy TOTP code"
			>
				<CopyIcon />
			</button>
		</div>
	);
}
