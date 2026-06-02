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
	parseTOML,
	readFileSync,
} from "@cloudflare/workers-utils";
import TOML from "smol-toml";
import type { UserAuthConfig } from "../config-file/auth";
import type { CredentialStore } from "./interface";

/**
 * Subdirectory under the global config path where auth files live.
 */
const USER_AUTH_CONFIG_PATH = "config";

/**
 * Absolute path to the plaintext TOML credentials file for the active
 * Cloudflare API environment.
 *
 * The environment is appended to the filename so callers running with
 * `WRANGLER_API_ENVIRONMENT=staging` get a separate file from production.
 * The path stays exposed so the migration code, defensive scrubs on
 * logout, and tests that assert against it can all point at the same
 * location as the {@link FileCredentialStore}.
 */
export function getAuthConfigFilePath(): string {
	const environment = getCloudflareApiEnvironmentFromEnv();
	const fileName =
		environment === "production" ? "default.toml" : `${environment}.toml`;
	return path.join(
		getGlobalWranglerConfigPath(),
		USER_AUTH_CONFIG_PATH,
		fileName
	);
}

/**
 * The historical plaintext-TOML credentials store.
 *
 * Used as the default backend when the user hasn't opted into keyring
 * storage, and as the soft-fallback when keyring storage is requested
 * but a backend isn't available.
 */
export class FileCredentialStore implements CredentialStore {
	readonly kind = "file" as const;

	read(): UserAuthConfig {
		// Matches the `AuthConfigStorage` contract: throw when nothing is
		// stored. `readStoredAuthState` and equivalents wrap this in
		// try/catch and treat throws as "not logged in".
		return parseTOML(readFileSync(getAuthConfigFilePath())) as UserAuthConfig;
	}

	write(config: UserAuthConfig): void {
		const filePath = getAuthConfigFilePath();
		mkdirSync(path.dirname(filePath), { recursive: true });
		// Mode `0o600` only applies on file creation, so we also re-chmod
		// every write to tighten any pre-existing file left behind by an
		// older Wrangler version that wrote with the process umask.
		writeFileSync(filePath, TOML.stringify(config), {
			encoding: "utf-8",
			mode: 0o600,
		});
		chmodSync(filePath, 0o600);
	}

	clear(): boolean {
		const filePath = getAuthConfigFilePath();
		const existed = existsSync(filePath);
		if (existed) {
			rmSync(filePath);
		}
		return existed;
	}

	path(): string {
		return getAuthConfigFilePath();
	}

	describe(): string {
		return getAuthConfigFilePath();
	}
}
