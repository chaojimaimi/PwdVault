import { useCallback, useEffect, useRef, useState } from "react";
import { totpCode } from "../api/vault";
import type { TotpCodeResponse } from "../types";
import { copyWithTimeout } from "../utils/clipboard";
import { showToast } from "../utils/toast";
import { CopyIcon } from "./Icons";

interface TotpCodeProps {
	entryId: string;
}

/**
 * Live TOTP code for a saved entry (Phase 2 / P3.5): shows the current
 * 6-digit code plus a per-second countdown, re-fetching from the backend
 * when the countdown expires so clock drift re-syncs with the real period.
 * Renders nothing while the entry has no configured secret (the backend
 * answers `TOTP_NOT_CONFIGURED`) or cannot be reached — the entry stays
 * editable either way.
 */
export function TotpCode({ entryId }: TotpCodeProps) {
	const [totp, setTotp] = useState<TotpCodeResponse | null>(null);
	const [secondsRemaining, setSecondsRemaining] = useState(0);
	const fetchingRef = useRef(false);

	const fetchCode = useCallback(async () => {
		if (fetchingRef.current) return;
		fetchingRef.current = true;
		try {
			const next = await totpCode(entryId);
			setTotp(next);
			setSecondsRemaining(next.seconds_remaining);
		} catch {
			// No secret configured / vault locked — hide the badge silently.
			setTotp(null);
		} finally {
			fetchingRef.current = false;
		}
	}, [entryId]);

	useEffect(() => {
		void fetchCode();
		// Decrement once per second; hitting zero triggers the refetch that
		// pulls the next period's code (equivalent to a 30s re-fetch, but
		// anchored to the backend-reported rotation point).
		const interval = window.setInterval(() => {
			setSecondsRemaining((s) => {
				if (s <= 1) {
					void fetchCode();
					return 0;
				}
				return s - 1;
			});
		}, 1000);
		return () => window.clearInterval(interval);
	}, [fetchCode]);

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
