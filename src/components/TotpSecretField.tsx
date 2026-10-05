import { EyeIcon, EyeOffIcon } from "./Icons";
import { TotpCode } from "./TotpCode";

interface TotpSecretFieldProps {
	/** Saved entry the live code view (TotpCode) polls for. */
	entryId: string;
	/** In-progress secret text; the parent owns the tri-state bookkeeping. */
	value: string;
	/** Whether the secret is shown in plain text (paste-only, never exposed by default). */
	visible: boolean;
	/** Reports each raw edit; the parent marks the tri-state as changed. */
	onChangeValue: (value: string) => void;
	onToggleVisible: () => void;
}

/**
 * TOTP secret editor (Phase 2), edit mode only. The tri-state semantics are
 * the same as update_notes: untouched (no totp_secret in the patch), cleared
 * ("" in the field), or set. New entries do not render this field —
 * create_entry has no TOTP field in the backend contract
 * (CreateEntryRequest), so they add TOTP via a second edit. The live code
 * view renders once the saved entry has a secret (TotpCode hides itself
 * while the backend reports none).
 */
export function TotpSecretField({
	entryId,
	value,
	visible,
	onChangeValue,
	onToggleVisible,
}: TotpSecretFieldProps) {
	const isOtpauthUri = value.trim().startsWith("otpauth://");
	return (
		<div className="form-group">
			<TotpCode entryId={entryId} />
			<label htmlFor="entry-totp">TOTP Secret</label>
			<div className="password-field">
				<input
					id="entry-totp"
					type={visible ? "text" : "password"}
					className="form-input"
					value={value}
					onChange={(e) => onChangeValue(e.target.value)}
					placeholder="Unchanged"
					autoComplete="off"
					spellCheck={false}
				/>
				<button
					type="button"
					onClick={onToggleVisible}
					aria-label={visible ? "Hide TOTP secret" : "Show TOTP secret"}
				>
					{visible ? <EyeOffIcon /> : <EyeIcon />}
				</button>
			</div>
			{isOtpauthUri ? (
				<p className="totp-hint totp-hint-active" role="status">
					otpauth:// URI detected — it will be saved as-is and the code
					parameters parsed automatically.
				</p>
			) : (
				<p className="totp-hint">
					Paste a base32 secret or a full otpauth:// URI. Clearing this
					field and saving removes the TOTP secret.
				</p>
			)}
		</div>
	);
}
