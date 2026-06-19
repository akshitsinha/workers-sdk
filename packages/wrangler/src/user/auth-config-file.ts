import {
	chmodSync,
	existsSync,
	mkdirSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import path from "node:path";
import { parseTOML, readFileSync } from "@cloudflare/workers-utils";
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

// `getAuthConfigFilePath` is owned by `@cloudflare/workers-auth` (it's the
// authority for the plaintext-TOML store's path layout, which the encrypted-
// file store also needs for legacy migration). Wrangler re-exports it from
// `./user` for back-compat with the historical wrangler-side import path.
export { getAuthConfigFilePath } from "@cloudflare/workers-auth";
