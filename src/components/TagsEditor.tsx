import { useState } from "react";

/**
 * Order-insensitive tags equality that PRESERVES duplicate multiplicity:
 * sort-then-join, deliberately not a Set — ["a", "a"] and ["a"] must stay
 * unequal or clearing a duplicate tag would not dirty the form.
 * (WP5 line-count reduction: moved verbatim out of EntryScreen, beside the
 * tags UI it belongs to.)
 */
export function sameTags(a: string[], b: string[]): boolean {
	if (a.length !== b.length) return false;
	const canonical = (tags: string[]) => [...tags].sort().join("\u0000");
	return canonical(a) === canonical(b);
}

interface TagsEditorProps {
	/** Current tag list; the parent owns it (it feeds the save patch). */
	value: string[];
	onChange: (tags: string[]) => void;
}

/**
 * Tags chip editor. Fully controlled: the parent owns the list, this
 * component holds only the in-progress input text. Adding trims and
 * de-duplicates against the current list; a rejected add (empty or duplicate)
 * intentionally keeps the input text so the user can correct it.
 */
export function TagsEditor({ value, onChange }: TagsEditorProps) {
	const [tagInput, setTagInput] = useState("");

	const addTag = () => {
		const tag = tagInput.trim();
		if (tag && !value.includes(tag)) {
			onChange([...value, tag]);
			setTagInput("");
		}
	};

	const removeTag = (tag: string) => {
		onChange(value.filter((t) => t !== tag));
	};

	return (
		<>
			<label htmlFor="tag-input" className="tag-label">
				Tags
			</label>
			<div className="entry-tags">
				{value.map((tag) => (
					<button
						key={tag}
						className="tag"
						type="button"
						onClick={() => removeTag(tag)}
						aria-label={`Remove tag ${tag}`}
					>
						{tag} ×
					</button>
				))}
			</div>
			<div className="tag-input-row">
				<input
					id="tag-input"
					type="text"
					className="form-input"
					value={tagInput}
					onChange={(e) => setTagInput(e.target.value)}
					onKeyDown={(e) => {
						// preventDefault: this input lives inside the entry form, so
						// an unprevented Enter would add the tag AND run the form's
						// implicit submission (saving the entry) in one keystroke.
						if (e.key === "Enter") {
							e.preventDefault();
							addTag();
						}
					}}
					placeholder="Add tag..."
				/>
				<button
					className="btn btn-secondary btn-inline"
					onClick={addTag}
					type="button"
				>
					Add
				</button>
			</div>
		</>
	);
}
