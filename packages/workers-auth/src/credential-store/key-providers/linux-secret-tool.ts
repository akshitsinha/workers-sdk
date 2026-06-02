import { spawnSync } from "node:child_process";
import {
	decodeKeyEnvelope,
	encodeKeyEnvelope,
	getKeyringAccountName,
} from "./shared";
import type { KeyProvider } from "./interface";
import type { SpawnSyncReturns } from "node:child_process";

/** Signature of the `secret-tool` invoker. Overridable for tests. */
export type LinuxSecretToolRunner = (
	args: string[],
	options?: { input?: string }
) => SpawnSyncReturns<string>;

function defaultRunner(
	args: string[],
	options: { input?: string } = {}
): SpawnSyncReturns<string> {
	return spawnSync("secret-tool", args, {
		encoding: "utf-8",
		input: options.input,
	});
}

let runner: LinuxSecretToolRunner = defaultRunner;

/**
 * Override the `secret-tool` invoker for tests. Pass `undefined` to restore
 * the default real-process runner.
 */
export function setLinuxSecretToolRunner(
	fn: LinuxSecretToolRunner | undefined
): void {
	runner = fn ?? defaultRunner;
}

/**
 * Probe whether `secret-tool` is callable in the current environment.
 *
 * Returns `true` when `secret-tool --version` exits 0. The probe does not
 * exercise the keyring backend itself — a missing D-Bus session surfaces
 * on the first real read/write rather than every consumer invocation, so
 * we avoid the extra latency on every command for users whose desktop
 * session is fully working.
 */
export function probeSecretTool(): boolean {
	try {
		const r = runner(["--version"]);
		return r.status === 0;
	} catch {
		return false;
	}
}

/**
 * Linux backend that stores the encryption key via libsecret's
 * `secret-tool` CLI.
 *
 * The key is passed to `secret-tool store` via stdin so it never appears
 * on the subprocess argv. Lookup writes the key envelope to stdout, which
 * is captured by `spawnSync`.
 *
 * `secret-tool` is part of the `libsecret-tools` package on most Linux
 * distros. The resolver in {@link "../resolver"} probes for its presence
 * and surfaces actionable install hints when missing; this class assumes
 * the tool is available.
 */
export class LinuxSecretToolKeyProvider implements KeyProvider {
	constructor(private readonly serviceName: string) {}

	getKey(): Uint8Array | undefined {
		const r = runner([
			"lookup",
			"service",
			this.serviceName,
			"account",
			getKeyringAccountName(),
		]);
		// `secret-tool lookup` exits 1 when no matching item is found.
		if (r.status === 1) {
			return undefined;
		}
		if (r.status !== 0) {
			throw new Error(
				`Failed to read key via secret-tool (exit ${r.status}): ${r.stderr?.trim() ?? "(no stderr)"}`
			);
		}
		return decodeKeyEnvelope(r.stdout);
	}

	setKey(key: Uint8Array): void {
		const r = runner(
			[
				"store",
				"--label=Cloudflare credentials key",
				"service",
				this.serviceName,
				"account",
				getKeyringAccountName(),
			],
			{ input: encodeKeyEnvelope(key) }
		);
		if (r.status !== 0) {
			throw new Error(
				`Failed to write key via secret-tool (exit ${r.status}): ${r.stderr?.trim() ?? "(no stderr)"}`
			);
		}
	}

	deleteKey(): void {
		const r = runner([
			"clear",
			"service",
			this.serviceName,
			"account",
			getKeyringAccountName(),
		]);
		// `secret-tool clear` is idempotent: exit 0 whether the item existed
		// or not. Any non-zero exit indicates a real failure (no D-Bus
		// session, locked keyring, etc.).
		if (r.status !== 0) {
			throw new Error(
				`Failed to delete key via secret-tool (exit ${r.status}): ${r.stderr?.trim() ?? "(no stderr)"}`
			);
		}
	}

	describe(): string {
		return `Linux secret-tool (service=${this.serviceName}, account=${getKeyringAccountName()})`;
	}
}
