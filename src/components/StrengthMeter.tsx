import { useMemo } from "react";
import { getGeneratorStrength } from "../utils/passwordStrength";
import type { GeneratorMode } from "../types";

interface StrengthMeterProps {
	password: string;
	/** v1.4.0: generator mode — switches the meter to parameter-based entropy
	 * for passphrase/PIN (the heuristic scorer is charset-password-specific). */
	mode?: GeneratorMode;
	/** Parameter values for the mode-aware entropy computation. */
	generatorParams?: { words?: number; appendNumber?: boolean; length?: number };
}

export function StrengthMeter({
	password,
	mode = "password",
	generatorParams,
}: StrengthMeterProps) {
	// §5.6.1: memoize the strength calculation so it only recomputes when the
	// password (or its parameters) change, not on every parent re-render.
	const strength = useMemo(
		() =>
			password
				? getGeneratorStrength(mode, password, generatorParams ?? {})
				: null,
		[password, mode, generatorParams],
	);
	if (!strength) return null;

	const strengthClass = strength.label.toLowerCase().replace(/\s+/g, "-");

	return (
		<div
			className="strength-meter"
			role="meter"
			aria-label={`Password strength: ${strength.label}`}
			aria-valuemin={0}
			aria-valuemax={100}
			aria-valuenow={strength.score}
			aria-valuetext={strength.label}
		>
			<progress
				className={`strength-track strength-${strengthClass}`}
				value={strength.score}
				max={100}
				aria-hidden="true"
			/>
			<span className={`strength-label strength-${strengthClass}`}>
				{strength.label}
			</span>
		</div>
	);
}
