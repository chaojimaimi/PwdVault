import { useState } from "react";
import { EyeIcon, EyeOffIcon, LockIcon } from "./Icons";

interface PasswordFieldProps {
	/** Input id — the label is associated via htmlFor. */
	id: string;
	label: string;
	value: string;
	onChange: (value: string) => void;
	placeholder?: string;
	disabled?: boolean;
	autoComplete?: string;
	/** Wired through to aria-invalid on the input. */
	ariaInvalid?: boolean;
	/** Wired through to aria-describedby on the input. */
	ariaDescribedBy?: string;
	/**
	 * jsx-a11y/no-autofocus: focus at commit instead of the autoFocus prop —
	 * same UX, programmatic. Only the screen's first field sets this.
	 */
	focusOnMount?: boolean;
}

/**
 * Auth-screen password input (v1.7.0 WP4): uppercase label, 15px lock icon,
 * show/hide eye toggle. Shared by Setup / Unlock / Recovery. Styling lives
 * in auth.css (.auth-* scope) — never the global .form-input/.btn classes.
 */
export function PasswordField({
	id,
	label,
	value,
	onChange,
	placeholder,
	disabled = false,
	autoComplete,
	ariaInvalid,
	ariaDescribedBy,
	focusOnMount = false,
}: PasswordFieldProps) {
	const [visible, setVisible] = useState(false);

	return (
		<div className="auth-group">
			<label className="auth-label" htmlFor={id}>
				{label}
			</label>
			<div className="auth-field auth-with-lock auth-with-eye">
				<LockIcon className="auth-lock-icon" />
				<input
					id={id}
					type={visible ? "text" : "password"}
					className="auth-input"
					value={value}
					onChange={(e) => onChange(e.target.value)}
					placeholder={placeholder}
					disabled={disabled}
					autoComplete={autoComplete}
					spellCheck={false}
					aria-invalid={ariaInvalid}
					aria-describedby={ariaDescribedBy}
					ref={(el) => {
						if (focusOnMount) {
							el?.focus();
						}
					}}
				/>
				<button
					type="button"
					className="auth-eye"
					onClick={() => setVisible((v) => !v)}
					aria-label={visible ? "Hide password" : "Show password"}
					disabled={disabled}
				>
					{visible ? <EyeOffIcon /> : <EyeIcon />}
				</button>
			</div>
		</div>
	);
}
