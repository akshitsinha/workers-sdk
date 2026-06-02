import {
	chmodSync,
	existsSync,
	mkdirSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import path from "node:path";
import {
	getCloudflareApiEnvironmentFromEnv,
	getGlobalWranglerConfigPath,
	readFileSync,
} from "@cloudflare/workers-utils";
import TOML from "smol-toml";
import {
	decryptString,
	encryptString,
	generateKey,
	parseEncryptedEnvelope,
} from "./crypto";
import { getAuthConfigFilePath } from "./file-store";
import type { UserAuthConfig } from "../config-file/auth";
import type { CredentialStore } from "./interface";
import type { KeyProvider } from "./key-providers/interface";

/**
 * Absolute path to the encrypted credentials file for the active
 * Cloudflare API environment.
 *
 * Sibling of the legacy plaintext `<env>.toml` so the migration code can
 * non-destructively read the old file before writing the new one.
 */
export function getEncryptedAuthConfigFilePath(): string {
	const environment = getCloudflareApiEnvironmentFromEnv();
	const fileName =
		environment === "production" ? "default.enc" : `${environment}.enc`;
	return path.join(getGlobalWranglerConfigPath(), "config", fileName);
}

/**
 * Result of a successful migration from a legacy plaintext TOML file
 * into an encrypted file backed by a `KeyProvider`. Surfaced so the
 * resolver can log a one-line summary when migration runs.
 */
export interface LegacyMigrationResult {
	legacyPath: string;
	encryptedPath: string;
	keyProviderDescription: string;
}

/**
 * Optional callback invoked by {@link EncryptedFileCredentialStore.read}
 * when it transparently migrates a legacy plaintext TOML file into the
 * encrypted file on first read.
 *
 * The resolver wires this to its logger; left undefined when the store
 * is constructed standalone (e.g. by tests).
 */
export type OnLegacyMigration = (result: LegacyMigrationResult) => void;

/**
 * Sentinel error thrown by {@link EncryptedFileCredentialStore.read} when
 * no credentials are stored. Matches the `AuthConfigStorage` "throw on
 * missing" contract; `readStoredAuthState` and equivalents wrap reads
 * in try/catch and treat throws as "not logged in".
 */
class NoCredentialsStoredError extends Error {
	constructor() {
		super("No credentials stored");
		this.name = "NoCredentialsStoredError";
	}
}

/**
 * Credentials store backed by an AES-256-GCM-encrypted file on disk and a
 * 32-byte encryption key held in the OS keyring via a {@link KeyProvider}.
 *
 * The combination decouples credential payload size from any per-platform
 * keyring item size limit (notably the ~2.5 KB macOS Keychain limit on
 * generic-password items): the keyring entry is always small (~44 bytes
 * of base64), while the credential blob lives in the encrypted file and
 * is free to grow as the schema evolves.
 *
 * Threat model:
 *   - File leaked from a backup without the keyring entry: ciphertext is
 *     useless, GCM auth tag prevents tampering.
 *   - Keyring entry leaked without the file: a bare 32-byte key, useless
 *     without the ciphertext.
 *   - Attacker with full local user access: can decrypt (same as
 *     direct-keyring storage — both backends expose secrets to root /
 *     same-user processes).
 */
export class EncryptedFileCredentialStore implements CredentialStore {
	readonly kind = "encrypted-file" as const;

	constructor(
		private readonly keyProvider: KeyProvider,
		private readonly onLegacyMigration?: OnLegacyMigration
	) {}

	read(): UserAuthConfig {
		const encryptedPath = getEncryptedAuthConfigFilePath();
		if (existsSync(encryptedPath)) {
			const value = this.readEncryptedFile(encryptedPath);
			if (value === undefined) {
				throw new NoCredentialsStoredError();
			}
			return value;
		}
		// No encrypted file yet — see if there's a legacy plaintext file we
		// should migrate into the encrypted layout. This makes opt-in
		// transparent: the next `read()` after the user runs
		// `wrangler login --use-keyring` returns the migrated credentials.
		const legacyPath = getAuthConfigFilePath();
		if (existsSync(legacyPath)) {
			const migrated = this.migrateFromLegacy(legacyPath, encryptedPath);
			if (migrated === undefined) {
				throw new NoCredentialsStoredError();
			}
			return migrated;
		}
		throw new NoCredentialsStoredError();
	}

	write(config: UserAuthConfig): void {
		const key = this.ensureKey();
		const plaintext = TOML.stringify(config);
		const envelope = encryptString(plaintext, key);
		const encryptedPath = getEncryptedAuthConfigFilePath();
		mkdirSync(path.dirname(encryptedPath), { recursive: true });
		writeFileSync(encryptedPath, JSON.stringify(envelope, null, "\t"), {
			encoding: "utf-8",
			mode: 0o600,
		});
		chmodSync(encryptedPath, 0o600);
		// Defensively scrub any legacy plaintext file once we've written
		// the encrypted version. Skipping this would leave plaintext
		// credentials on disk indefinitely after the very first
		// `--use-keyring` login.
		const legacyPath = getAuthConfigFilePath();
		if (existsSync(legacyPath)) {
			rmSync(legacyPath);
		}
	}

	clear(): boolean {
		const encryptedPath = getEncryptedAuthConfigFilePath();
		const legacyPath = getAuthConfigFilePath();
		let existed = false;
		if (existsSync(encryptedPath)) {
			rmSync(encryptedPath);
			existed = true;
		}
		// Also scrub any legacy plaintext file, in case the user toggled
		// backends in a previous session and the legacy file lingered.
		if (existsSync(legacyPath)) {
			rmSync(legacyPath);
			existed = true;
		}
		try {
			this.keyProvider.deleteKey();
		} catch {
			// `deleteKey()` is documented as idempotent; some backends
			// surface NoEntry on a missing key, which is fine here.
		}
		return existed;
	}

	path(): string {
		return getEncryptedAuthConfigFilePath();
	}

	describe(): string {
		return `Encrypted file (${getEncryptedAuthConfigFilePath()}) with key in ${this.keyProvider.describe()}`;
	}

	/* ------------------------------------------------------------------ */
	/* Internals                                                           */
	/* ------------------------------------------------------------------ */

	private readEncryptedFile(encryptedPath: string): UserAuthConfig | undefined {
		const key = this.keyProvider.getKey();
		if (key === undefined) {
			// File present but key missing — treat as "not logged in" so
			// the next login regenerates the key and re-encrypts. Matches
			// the historical "no file → not logged in" semantics.
			return undefined;
		}
		let envelope;
		try {
			envelope = parseEncryptedEnvelope(
				JSON.parse(readFileSync(encryptedPath))
			);
		} catch {
			// Malformed JSON — treat as corrupted and let the next write
			// overwrite it.
			return undefined;
		}
		if (envelope === undefined) {
			return undefined;
		}
		let plaintext: string;
		try {
			plaintext = decryptString(envelope, key);
		} catch {
			// Authentication tag mismatch (tampered file or wrong key) —
			// treat as "not logged in".
			return undefined;
		}
		try {
			return TOML.parse(plaintext) as unknown as UserAuthConfig;
		} catch {
			// Plaintext decrypted but is not valid TOML — corrupted.
			return undefined;
		}
	}

	private migrateFromLegacy(
		legacyPath: string,
		encryptedPath: string
	): UserAuthConfig | undefined {
		let legacy: UserAuthConfig;
		try {
			legacy = TOML.parse(
				readFileSync(legacyPath)
			) as unknown as UserAuthConfig;
		} catch {
			// Legacy file is unreadable — bail out rather than partially
			// migrate. The caller will treat this as "not logged in" and
			// the user will need to re-login.
			return undefined;
		}
		this.write(legacy);
		this.onLegacyMigration?.({
			legacyPath,
			encryptedPath,
			keyProviderDescription: this.keyProvider.describe(),
		});
		return legacy;
	}

	/**
	 * Return the existing encryption key, or generate + persist a fresh
	 * one when none exists yet. Called from `write()` so the first
	 * `wrangler login --use-keyring` is fully bootstrapping.
	 */
	private ensureKey(): Uint8Array {
		const existing = this.keyProvider.getKey();
		if (existing !== undefined) {
			return existing;
		}
		const fresh = generateKey();
		this.keyProvider.setKey(fresh);
		return fresh;
	}
}
