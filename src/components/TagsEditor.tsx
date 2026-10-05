import { useState } from "react";

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
					onKeyDown={(e) => e.key === "Enter" && addTag()}
					placeholder="Add tag..."
				/>
				<button
					className="btn btn-secondary"
					onClick={addTag}
					type="button"
				>
					Add
				</button>
			</div>
		</>
	);
}
