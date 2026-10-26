import { useState } from "react";
import { generatePassword } from "../api/vault";
import { AccessibleDialog } from "./AccessibleDialog";

interface EntryGeneratorModalProps {
	isOpen: boolean;
	onClose: () => void;
	/** Inserts the generated password into the entry form and closes. */
	onUse: (password: string) => void;
	/** Surfaces generation failures on the entry form's error line. */
	onError: (message: string) => void;
	/** Saved generator defaults (same source as GeneratorScreen, A5). */
	options: {
		length: number;
		includeUppercase: boolean;
		includeLowercase: boolean;
		includeNumbers: boolean;
		includeSymbols: boolean;
	};
}

/**
 * Entry-screen quick generator modal (WP5 line-count reduction: moved
 * verbatim out of EntryScreen, which keeps only the open/close wiring and
 * the use-password callback). Owns the generated-value state — it survives
 * close/reopen until a password is used, matching the original inline
 * modal's behavior.
 */
export function EntryGeneratorModal({
	isOpen,
	onClose,
	onUse,
	onError,
	options,
}: EntryGeneratorModalProps) {
	const [generatedPassword, setGeneratedPassword] = useState("");

	const handleGeneratePassword = async () => {
		try {
			const pwd = await generatePassword(options);
			setGeneratedPassword(pwd);
		} catch {
			onError("Failed to generate password");
		}
	};

	const handleUseGenerated = () => {
		onUse(generatedPassword);
		setGeneratedPassword("");
	};

	return (
		<AccessibleDialog
			isOpen={isOpen}
			onClose={onClose}
			labelledBy="entry-generator-title"
			describedBy="entry-generator-description"
			initialFocusSelector="[data-generate-password]"
		>
			<div className="modal-header">
				<h3 id="entry-generator-title">Generate Password</h3>
				<button
					className="btn btn-icon"
					onClick={onClose}
					aria-label="Close generator"
				>
					×
				</button>
			</div>
			<div className="modal-body">
				<p id="entry-generator-description" className="visually-hidden">
					Generate a password and insert it into this entry.
				</p>
				<div className="password-preview">
					{generatedPassword || "Click generate to create a password"}
				</div>
				<button
					className="btn btn-secondary"
					data-generate-password
					onClick={handleGeneratePassword}
				>
					Generate New
				</button>
			</div>
			<div className="modal-footer">
				<button className="btn btn-secondary" onClick={onClose}>
					Cancel
				</button>
				<button
					className="btn btn-primary"
					onClick={handleUseGenerated}
					disabled={!generatedPassword}
				>
					Use Password
				</button>
			</div>
		</AccessibleDialog>
	);
}
