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
import type { ConfigStorage } from "@cloudflare/workers-auth";

/**
 * A TOML-file-on-disk storage backend, parameterised by the path it reads and
 * writes. Used by the temporary-preview-account store
 * (`defaultTemporaryAccountStorage`) and as the building block underneath the
 * `FileCredentialStore` exported from `@cloudflare/workers-auth` (which is
 * what wrangler's `credentialStorage` bundle returns when keyring storage is
 * not active).
 *
 * `read()` throws when the file is missing or cannot be parsed — callers treat a
 * throw as "nothing stored". Files are written with mode `0o600` on creation and
 * re-`chmod`'d on every save (the `mode` option only applies on creation) so
 * other local users on shared hosts can't read the stored credentials.
 */
export function createTomlFileStorage<T extends object>(
	getPath: () => string
): ConfigStorage<T> {
	return {
		read: () => parseTOML(readFileSync(getPath())) as T,
		write(config) {
			const configPath = getPath();
			mkdirSync(path.dirname(configPath), { recursive: true });
			writeFileSync(configPath, TOML.stringify(config), {
				encoding: "utf-8",
				mode: 0o600,
			});
			chmodSync(configPath, 0o600);
		},
		clear() {
			const configPath = getPath();
			const existed = existsSync(configPath);
			rmSync(configPath, { force: true });
			return existed;
		},
		path: getPath,
	};
}

/**
 * The path to the config file that holds user authentication data,
 * relative to the user's home directory.
 */
const USER_AUTH_CONFIG_PATH = "config";

/**
 * Returns the absolute path to the auth config TOML file.
 *
 * The file lives under the global Wrangler config directory and is named
 * `default.toml` in production, or `<environment>.toml` for the staging /
 * other Cloudflare API environments.
 *
 * Kept in sync with the `getAuthConfigFilePath` implementation in
 * `@cloudflare/workers-auth/src/credential-store/file-store.ts` so the
 * encrypted-file legacy-migration code finds the same file that wrangler
 * tests and `whoami` assert against.
 */
export function getAuthConfigFilePath(): string {
	const environment = getCloudflareApiEnvironmentFromEnv();
	const filePath = `${USER_AUTH_CONFIG_PATH}/${environment === "production" ? "default.toml" : `${environment}.toml`}`;
	return path.join(getGlobalWranglerConfigPath(), filePath);
}
