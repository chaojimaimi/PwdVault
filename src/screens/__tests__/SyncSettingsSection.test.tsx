import { render, fireEvent, screen, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";

const showToast = vi.fn();

vi.mock("../../utils/toast", () => ({ showToast }));

const loadEntries = vi.fn();
const loadGroups = vi.fn();

vi.mock("../../context/VaultContext", () => ({
	useVault: () => ({ actions: { loadEntries, loadGroups } }),
}));

const syncStatus = vi.fn();
const syncConnect = vi.fn();
const syncDisconnect = vi.fn();
const syncNow = vi.fn();
const baiduStartAuth = vi.fn();
const baiduCompleteAuth = vi.fn();

vi.mock("../../api/vault", () => ({
	syncStatus: (...args: unknown[]) => syncStatus(...args),
	syncConnect: (...args: unknown[]) => syncConnect(...args),
	syncDisconnect: (...args: unknown[]) => syncDisconnect(...args),
	syncNow: (...args: unknown[]) => syncNow(...args),
	baiduStartAuth: (...args: unknown[]) => baiduStartAuth(...args),
	baiduCompleteAuth: (...args: unknown[]) => baiduCompleteAuth(...args),
}));

beforeEach(() => {
	vi.clearAllMocks();
	// Default: sync not configured (bootstrap form).
	syncStatus.mockResolvedValue({
		enabled: false,
		backend: null,
		last_sync_at: null,
		last_result: null,
		remote_rev: null,
	});
	loadEntries.mockResolvedValue(undefined);
	loadGroups.mockResolvedValue(undefined);
});

async function renderSection() {
	const { SyncSettingsSection } = await import(
		"../../components/SyncSettingsSection"
	);
	return render(<SyncSettingsSection />);
}

const NOT_CONFIGURED_ERROR = {
	InvalidInput: {
		code: "SYNC_BACKEND_NOT_CONFIGURED",
		message: "Baidu Netdisk backend is not configured in this build",
	},
};

describe("SyncSettingsSection not-connected state", () => {
	it("renders the backend choice and the WebDAV bootstrap form", async () => {
		await renderSection();

		expect(await screen.findByText("Cloud Sync")).toBeInTheDocument();
		expect(screen.getByLabelText("Backend")).toHaveValue("webdav");
		expect(screen.getByLabelText("Server URL")).toBeInTheDocument();
		expect(screen.getByLabelText("Remote directory")).toBeInTheDocument();
		expect(screen.getByLabelText("Username")).toBeInTheDocument();
		expect(screen.getByLabelText("Password")).toBeInTheDocument();
		expect(screen.getByLabelText("Container password")).toBeInTheDocument();
		expect(
			screen.getByRole("button", { name: "Connect" }),
		).toBeInTheDocument();
		// Connected-only affordances stay hidden.
		expect(
			screen.queryByRole("button", { name: "Sync Now" }),
		).not.toBeInTheDocument();
		expect(
			screen.queryByRole("button", { name: "Disconnect" }),
		).not.toBeInTheDocument();
	});

	it("rejects an empty WebDAV form without calling the backend", async () => {
		await renderSection();

		fireEvent.click(await screen.findByRole("button", { name: "Connect" }));

		expect(
			await screen.findByText("Enter your WebDAV server URL"),
		).toBeInTheDocument();
		expect(syncConnect).not.toHaveBeenCalled();
	});

	it("connects WebDAV with the container password and refreshes status", async () => {
		syncConnect.mockResolvedValue({
			enabled: true,
			backend: "webdav",
			last_sync_at: 1700000000,
			last_result: "ok",
			remote_rev: 3,
		});
		await renderSection();

		fireEvent.change(screen.getByLabelText("Server URL"), {
			target: { value: "https://dav.jianguoyun.com/dav" },
		});
		fireEvent.change(screen.getByLabelText("Remote directory"), {
			target: { value: "PwdVault" },
		});
		fireEvent.change(screen.getByLabelText("Username"), {
			target: { value: "me@example.com" },
		});
		fireEvent.change(screen.getByLabelText("Password"), {
			target: { value: "app-password" },
		});
		fireEvent.change(screen.getByLabelText("Container password"), {
			target: { value: "container-pass" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Connect" }));

		await waitFor(() =>
			expect(syncConnect).toHaveBeenCalledWith(
				{
					enabled: true,
					backend: "webdav",
					server_url: "https://dav.jianguoyun.com/dav",
					remote_dir: "PwdVault",
					username: "me@example.com",
				},
				"container-pass",
				"app-password",
			),
		);
		expect(showToast).toHaveBeenCalledWith("Cloud sync connected");
		// Status refresh flips the section into the connected view.
		expect(
			await screen.findByRole("button", { name: "Sync Now" }),
		).toBeInTheDocument();
	});

	it("shows the container password and a gated Connect for the Baidu backend", async () => {
		await renderSection();

		fireEvent.change(await screen.findByLabelText("Backend"), {
			target: { value: "baidu" },
		});
		// Baidu needs no WebDAV form, but the container password bootstrap
		// (D2) applies to both backends.
		expect(screen.queryByLabelText("Server URL")).not.toBeInTheDocument();
		expect(screen.queryByLabelText("Password")).not.toBeInTheDocument();
		expect(screen.getByLabelText("Container password")).toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Connect" })).toBeDisabled();
		expect(baiduCompleteAuth).not.toHaveBeenCalled();
	});
});

describe("SyncSettingsSection Baidu authorization", () => {
	it("shows the BAIDU-SETUP guidance when the backend is not configured", async () => {
		baiduStartAuth.mockRejectedValue(NOT_CONFIGURED_ERROR);
		await renderSection();

		fireEvent.change(await screen.findByLabelText("Backend"), {
			target: { value: "baidu" },
		});
		fireEvent.click(
			screen.getByRole("button", { name: "Authorize Baidu Netdisk" }),
		);

		expect(await screen.findByText(/not configured in this build/))
			.toBeInTheDocument();
		expect(screen.getByText("docs/BAIDU-SETUP.md")).toBeInTheDocument();
		expect(baiduCompleteAuth).not.toHaveBeenCalled();
	});

	it("opens the authorize URL, completes the OAuth code, and connects", async () => {
		const openSpy = vi
			.spyOn(window, "open")
			.mockImplementation(() => null);
		baiduStartAuth.mockResolvedValue({
			auth_url: "https://openapi.baidu.com/oauth/2.0/authorize?client_id=x",
		});
		baiduCompleteAuth.mockResolvedValue(undefined);
		syncConnect.mockResolvedValue({
			enabled: true,
			backend: "baidu",
			last_sync_at: 1700000000,
			last_result: "ok",
			remote_rev: 5,
		});
		// Mount probe and post-auth refresh stay not-enabled — only a
		// successful syncConnect flips the section into the connected view.
		const NOT_ENABLED = {
			enabled: false,
			backend: null,
			last_sync_at: null,
			last_result: null,
			remote_rev: null,
		};
		syncStatus
			.mockResolvedValueOnce(NOT_ENABLED)
			.mockResolvedValueOnce(NOT_ENABLED)
			.mockResolvedValue({
				enabled: true,
				backend: "baidu",
				last_sync_at: 1700000000,
				last_result: "ok",
				remote_rev: 5,
			});
		await renderSection();

		fireEvent.change(await screen.findByLabelText("Backend"), {
			target: { value: "baidu" },
		});
		fireEvent.click(
			screen.getByRole("button", { name: "Authorize Baidu Netdisk" }),
		);

		// Browser opens the authorize page without opener access.
		expect(await screen.findByRole("button", { name: "I've authorized" }))
			.toBeInTheDocument();
		expect(openSpy).toHaveBeenCalledWith(
			"https://openapi.baidu.com/oauth/2.0/authorize?client_id=x",
			"_blank",
			"noopener,noreferrer",
		);

		fireEvent.click(screen.getByRole("button", { name: "I've authorized" }));
		await waitFor(() =>
			expect(baiduCompleteAuth).toHaveBeenCalledWith(null),
		);
		expect(showToast).toHaveBeenCalledWith("Baidu Netdisk authorized");

		// Connect gates on the container password even after authorization.
		fireEvent.click(screen.getByRole("button", { name: "Connect" }));
		expect(syncConnect).not.toHaveBeenCalled();
		fireEvent.change(screen.getByLabelText("Container password"), {
			target: { value: "container-pass" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Connect" }));
		await waitFor(() =>
			expect(syncConnect).toHaveBeenCalledWith(
				{
					enabled: true,
					backend: "baidu",
					server_url: "",
					remote_dir: "",
					username: "",
				},
				"container-pass",
				null,
			),
		);
		// Status refresh after the connect shows the connected view.
		expect(
			await screen.findByRole("button", { name: "Sync Now" }),
		).toBeInTheDocument();
	});
});

describe("SyncSettingsSection connected state", () => {
	const CONNECTED = {
		enabled: true,
		backend: "webdav",
		last_sync_at: 1700000000,
		last_result: "ok",
		remote_rev: 7,
	};

	beforeEach(() => {
		syncStatus.mockResolvedValue(CONNECTED);
	});

	it("shows the status row and runs a manual sync", async () => {
		syncNow.mockResolvedValue({ ...CONNECTED, remote_rev: 8 });
		await renderSection();

		// "Remote revision" only exists in the connected view — a stable
		// readiness marker that avoids racing the initial status probe.
		expect(await screen.findByText("Remote revision")).toBeInTheDocument();
		expect(screen.getByText("WebDAV")).toBeInTheDocument();
		expect(screen.getByText("7")).toBeInTheDocument();
		expect(
			screen.getByRole("button", { name: "Sync Now" }),
		).toBeInTheDocument();

		fireEvent.click(screen.getByRole("button", { name: "Sync Now" }));
		await waitFor(() => expect(syncNow).toHaveBeenCalledOnce());
		expect(showToast).toHaveBeenCalledWith("Sync completed");
		// The status line reflects the refreshed payload.
		expect(await screen.findByText("8")).toBeInTheDocument();
	});

	it("surfaces sync failures from the backend", async () => {
		syncNow.mockRejectedValue({
			InternalError: "cloud unreachable",
		});
		await renderSection();

		fireEvent.click(await screen.findByRole("button", { name: "Sync Now" }));
		await waitFor(() =>
			expect(showToast).toHaveBeenCalledWith(
				expect.stringContaining("cloud unreachable"),
			),
		);
		// Backend failure: no local refresh is attempted.
		expect(loadEntries).not.toHaveBeenCalled();
		expect(loadGroups).not.toHaveBeenCalled();
	});

	it("refreshes the vault lists after a successful sync", async () => {
		syncNow.mockResolvedValue({ ...CONNECTED, remote_rev: 9 });
		await renderSection();

		fireEvent.click(await screen.findByRole("button", { name: "Sync Now" }));
		await waitFor(() =>
			expect(showToast).toHaveBeenCalledWith("Sync completed"),
		);
		// H3: remote changes must show up without remounting the screen.
		expect(loadEntries).toHaveBeenCalledOnce();
		expect(loadGroups).toHaveBeenCalledOnce();
	});

	it("reports a failed local refresh after a successful sync", async () => {
		syncNow.mockResolvedValue({ ...CONNECTED, remote_rev: 10 });
		loadEntries.mockRejectedValue(new Error("reload boom"));
		await renderSection();

		fireEvent.click(await screen.findByRole("button", { name: "Sync Now" }));
		await waitFor(() =>
			expect(showToast).toHaveBeenCalledWith(
				"Sync completed, but local list refresh failed",
			),
		);
		// The success toast must not fire alongside the refresh-failure toast.
		expect(showToast).not.toHaveBeenCalledWith("Sync completed");
	});

	it("disconnects only after confirmation and returns to the bootstrap form", async () => {
		syncDisconnect.mockResolvedValue(undefined);
		syncStatus.mockResolvedValueOnce(CONNECTED).mockResolvedValue({
			enabled: false,
			backend: null,
			last_sync_at: null,
			last_result: null,
			remote_rev: null,
		});
		await renderSection();

		await screen.findByRole("button", { name: "Sync Now" });
		expect(syncDisconnect).not.toHaveBeenCalled();

		// First click opens the confirmation dialog (page-level button).
		fireEvent.click(screen.getByRole("button", { name: "Disconnect" }));
		// Confirmation dialog gates the backend call (dialog-level button).
		const dialogDisconnect = (
			await screen.findAllByRole("button", { name: "Disconnect" })
		).pop()!;
		fireEvent.click(dialogDisconnect);

		await waitFor(() => expect(syncDisconnect).toHaveBeenCalledOnce());
		expect(showToast).toHaveBeenCalledWith(
			expect.stringContaining("Cloud files are kept"),
		);
		expect(
			await screen.findByRole("button", { name: "Connect" }),
		).toBeInTheDocument();
	});
});
