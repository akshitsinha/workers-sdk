import { resolveKeyringEntryFactory } from "./lazy-installer";
import {
	decodeKeyEnvelope,
	encodeKeyEnvelope,
	getKeyringAccountName,
} from "./shared";
import type { KeyProvider } from "./interface";
import type { KeyringEntry } from "./lazy-installer";

/**
 * Backend that stores the encryption key via `@napi-rs/keyring`'s
 * native `Entry` class.
 *
 * Used on Windows once the binding has been lazy-installed (via the
 * resolver), and by tests on every platform that register an in-memory
 * `KeyringEntryFactory` via {@link setKeyringEntryFactory}.
 *
 * On Windows the binding talks to the Credential Manager wincred API.
 * On macOS / Linux (when used by tests), the test factory short-circuits
 * the lazy load so no real keychain is touched.
 */
export class NapiKeyringKeyProvider implements KeyProvider {
	constructor(private readonly serviceName: string) {}

	private entry(): KeyringEntry {
		return resolveKeyringEntryFactory()(
			this.serviceName,
			getKeyringAccountName()
		);
	}

	getKey(): Uint8Array | undefined {
		const raw = this.entry().getPassword();
		if (raw === null || raw === "") {
			return undefined;
		}
		return decodeKeyEnvelope(raw);
	}

	setKey(key: Uint8Array): void {
		this.entry().setPassword(encodeKeyEnvelope(key));
	}

	deleteKey(): void {
		try {
			this.entry().deletePassword();
		} catch {
			// `deletePassword` throws `NoEntry` when no entry exists yet,
			// which is fine — `deleteKey()` is documented as idempotent.
		}
	}

	describe(): string {
		const platformName =
			process.platform === "win32"
				? "Windows Credential Manager"
				: "OS keyring";
		return `${platformName} via @napi-rs/keyring (service=${this.serviceName}, account=${getKeyringAccountName()})`;
	}
}
