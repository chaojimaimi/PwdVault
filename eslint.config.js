import js from "@eslint/js";
import tseslint from "typescript-eslint";
import globals from "globals";
import jsxA11y from "eslint-plugin-jsx-a11y";
import reactHooks from "eslint-plugin-react-hooks";

export default tseslint.config(
	{
		ignores: [
			"dist/**",
			// Only the firefox copy is excluded: it symlinks the shared chrome
			// sources, so linting both would double-report every finding. The
			// chrome sources ARE linted (v1.3.2).
			"extensions/firefox/**",
			"releases/**",
			"src-tauri/**",
			"scripts/**",
			"**/*.mjs",
		],
	},
	js.configs.recommended,
	...tseslint.configs.recommended,
	jsxA11y.flatConfigs.recommended,
	{
		plugins: { "react-hooks": reactHooks },
		rules: {
			"react-hooks/rules-of-hooks": "error",
			"react-hooks/exhaustive-deps": "warn",
		},
	},
	{
		languageOptions: {
			globals: {
				...globals.browser,
				...globals.node,
			},
		},
		rules: {
			"@typescript-eslint/no-unused-vars": [
				"warn",
				{ argsIgnorePattern: "^_" },
			],
			"@typescript-eslint/no-explicit-any": "warn",
			"no-useless-catch": "off",
		},
	},
	{
		// Extension sources (MV3 service worker / content / popup scripts).
		// chrome/browser are the extension API namespaces; window/document are
		// already covered by globals.browser above but are pinned here so this
		// block stays self-describing.
		files: ["extensions/chrome/src/**/*.js"],
		languageOptions: {
			globals: {
				chrome: "readonly",
				browser: "readonly",
				window: "readonly",
				document: "readonly",
			},
		},
	},
);
