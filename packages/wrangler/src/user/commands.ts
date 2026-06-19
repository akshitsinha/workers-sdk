import { existsSync, rmSync } from "node:fs";
import {
	EncryptedFileCredentialStore,
	getCloudflareAuthUseKeyringFromEnv,
	getEncryptedAuthConfigFilePath,
	resolveKeyProvider,
} from "@cloudflare/workers-auth";
import { CommandLineArgsError, UserError } from "@cloudflare/workers-utils";
import { readConfig } from "../config";
import { createCommand, createNamespace } from "../core/create-command";
import { logger } from "../logger";
import * as metrics from "../metrics";
import { readUserPreferences, updateUserPreferences } from "./preferences";
import {
	DefaultScopeKeys,
	getAuthFromEnv,
	getCredentialStore,
	getOAuthTokenFromLocalState,
	listScopes,
	login,
	logout,
	validateScopeKeys,
	WRANGLER_KEYRING_SERVICE_NAME,
} from "./user";
import { whoami } from "./whoami";

/**
 * Represents the authentication information returned by `wrangler auth token --json`.
 */
export type AuthTokenInfo =
	| { type: "oauth"; token: string }
	| { type: "api_token"; token: string }
	| { type: "api_key"; key: string; email: string };

export const loginCommand = createCommand({
	metadata: {
		description: "🔓 Login to Cloudflare",
		owner: "Workers: Authoring and Testing",
		status: "stable",
		category: "Account",
	},
	behaviour: {
		printConfigWarnings: false,
		suggestSkillsAfterHandler: true,
	},
	args: {
		"scopes-list": {
			describe: "List all the available OAuth scopes with descriptions",
		},
		browser: {
			default: true,
			type: "boolean",
			describe: "Automatically open the OAuth link in a browser",
		},
		scopes: {
			describe: "Pick the set of applicable OAuth scopes when logging in",
			array: true,
			type: "string",
			requiresArg: true,
		},
		"callback-host": {
			describe:
				"Use the ip or host address for the temporary login callback server.",
			type: "string",
			requiresArg: false,
			default: "localhost",
		},
		"callback-port": {
			describe: "Use the port for the temporary login callback server.",
			type: "number",
			requiresArg: false,
			default: 8976,
		},
		"use-keyring": {
			describe:
				"Store OAuth credentials in the OS keychain (macOS Keychain, " +
				"Windows Credential Manager, libsecret) instead of a plaintext " +
				"TOML file. Pass `--no-use-keyring` to opt back out. The choice " +
				"is persisted across `wrangler` invocations.",
			type: "boolean",
		},
	},
	async handler(args, { config }) {
		if (args.scopesList) {
			listScopes();
			return;
		}

		// Persist `--use-keyring` / `--no-use-keyring` before doing the login
		// so the OAuth callback writes credentials to the requested backend.
		// The `CLOUDFLARE_AUTH_USE_KEYRING` env var still wins over the
		// persistent preference, but we warn so the user isn't surprised.
		if (args.useKeyring !== undefined) {
			const previouslyEnabled = readUserPreferences().keyring_enabled === true;
			const envOverride = getCloudflareAuthUseKeyringFromEnv();
			if (envOverride !== undefined && envOverride !== args.useKeyring) {
				logger.warn(
					`CLOUDFLARE_AUTH_USE_KEYRING=${envOverride} overrides the --${args.useKeyring ? "use-keyring" : "no-use-keyring"} flag for this command.`
				);
			}

			if (!args.useKeyring && previouslyEnabled) {
				// Opting out: scrub the encrypted credentials and the keyring
				// entry **without** decrypting them into a plaintext file —
				// writing plaintext on disk during opt-out would defeat the
				// at-rest protection the user just chose to disable, leaving
				// the same credentials they wanted out of plaintext sitting
				// on disk in plaintext anyway.
				//
				// We bypass `getCredentialStore()` here because the resolver
				// short-circuits to `FileCredentialStore` when
				// `CLOUDFLARE_AUTH_USE_KEYRING=false` is set in the
				// environment (see `resolver.ts`). `FileCredentialStore.delete()`
				// only removes the plaintext `.toml`, which would leave the
				// `.enc` file and the keyring entry intact. Resolving the
				// encrypted store directly guarantees the scrub always
				// targets the backend the user is opting *out of*,
				// regardless of the env-var state.
				try {
					const resolution = resolveKeyProvider(WRANGLER_KEYRING_SERVICE_NAME);
					if (resolution.kind === "available") {
						new EncryptedFileCredentialStore(resolution.provider).clear();
						logger.log(
							"Removed the encrypted credentials and the keyring entry. Run `wrangler login` to log in again."
						);
					} else {
						// The keyring backend is unreachable on this host right
						// now (e.g. Linux without `secret-tool`, Windows without
						// the lazy-installed `@napi-rs/keyring` binding). The
						// user previously opted in successfully, so an `.enc`
						// file may still be on disk — scrub it best-effort. The
						// ciphertext is useless without the key, but stale
						// files are confusing and could collide with a future
						// opt-in.
						const encryptedPath = getEncryptedAuthConfigFilePath();
						if (existsSync(encryptedPath)) {
							rmSync(encryptedPath);
						}
						logger.warn(
							"Removed the encrypted credentials file, but the keyring backend was not reachable on this host so the keyring entry could not be cleared. Clear it manually if it persists. Run `wrangler login` to log in again."
						);
					}
				} catch (e) {
					logger.warn(
						`Failed to remove encrypted credentials on opt-out: ${
							e instanceof Error ? e.message : String(e)
						}. You may need to clear them manually before logging in again.`
					);
				}
			}

			updateUserPreferences({ keyring_enabled: args.useKeyring });

			if (args.useKeyring) {
				// Resolve the credential store eagerly so any platform-specific
				// install (Windows lazy-install of @napi-rs/keyring) or probe
				// failure (Linux missing secret-tool, CI without TTY) surfaces
				// before the user sits through the OAuth flow.
				//
				// `getCredentialStore()` re-reads the persisted preference, so
				// we have to persist *before* validating. Roll the persist
				// back in *two* cases so a failed opt-in doesn't leave
				// `keyring_enabled: true` on disk:
				//
				//  1. The resolver threw (e.g. CLOUDFLARE_AUTH_USE_KEYRING=true
				//     forced + unsupported platform, Windows install failure
				//     when forced, non-interactive Linux without secret-tool).
				//  2. The resolver soft-fell-back to the plaintext file store
				//     (interactive Linux without secret-tool, unsupported
				//     platform without env-var force, Windows install failure
				//     not forced). The resolver already warned the user; we
				//     just need to make sure we don't persist the opt-in on
				//     top of that warning, because every future command would
				//     then re-resolve, soft-fall-back again, and warn again
				//     until the user explicitly ran `--no-use-keyring`.
				try {
					const store = getCredentialStore();
					if (store.kind !== "encrypted-file") {
						updateUserPreferences({ keyring_enabled: previouslyEnabled });
						logger.warn(
							"Keyring storage isn't available on this host (see warning above), so `--use-keyring` was not persisted. Re-run `wrangler login --use-keyring` once the keyring backend is reachable."
						);
					}
				} catch (e) {
					updateUserPreferences({ keyring_enabled: previouslyEnabled });
					throw e;
				}
			}
		}

		// Validate `--scopes` up front so we can share a single `login(...)`
		// call (and a single `sendMetricsEvent("login user", ...)` site) between
		// the scoped and unscoped paths.
		let scopes: typeof DefaultScopeKeys | undefined;
		if (args.scopes) {
			if (args.scopes.length === 0) {
				// don't allow no scopes to be passed, that would be weird
				listScopes();
				return;
			}
			if (!validateScopeKeys(args.scopes)) {
				const validSet = new Set<string>(DefaultScopeKeys);
				const invalidScopes = args.scopes.filter((s) => !validSet.has(s));
				throw new CommandLineArgsError(
					`Invalid authentication scope${invalidScopes.length > 1 ? "s" : ""}: ${invalidScopes.map((s) => `"${s}"`).join(", ")}. Run "wrangler login --scopes-list" to see all valid scopes.`,
					{ telemetryMessage: "user login invalid scope" }
				);
			}
			scopes = args.scopes;
		}
		await login(config, {
			scopes,
			browser: args.browser,
			callbackHost: args.callbackHost,
			callbackPort: args.callbackPort,
		});
		metrics.sendMetricsEvent("login user", {
			sendMetrics: config.send_metrics,
		});

		// TODO: would be nice if it optionally saved login
		// credentials inside node_modules/.cache or something
		// this way you could have multiple users on a single machine
	},
});

export const logoutCommand = createCommand({
	metadata: {
		description: "🚪 Logout from Cloudflare",
		owner: "Workers: Authoring and Testing",
		status: "stable",
		category: "Account",
	},
	behaviour: {
		printConfigWarnings: false,
		provideConfig: false,
		suggestSkillsAfterHandler: true,
	},
	async handler() {
		await logout();
		try {
			// If the config file is invalid then we default to not sending metrics.
			// TODO: Clean this up as part of a general config refactor.
			// See https://github.com/cloudflare/workers-sdk/issues/10682.
			const config = readConfig({}, { hideWarnings: true });
			metrics.sendMetricsEvent("logout user", {
				sendMetrics: config.send_metrics,
			});
		} catch (e) {
			logger.debug("Could not read config to send logout metrics.", e);
		}
	},
});

export const whoamiCommand = createCommand({
	metadata: {
		description: "🕵️ Retrieve your user information",
		owner: "Workers: Authoring and Testing",
		status: "stable",
		category: "Account",
	},
	behaviour: {
		printBanner: (args) => !args.json,
		printConfigWarnings: false,
		suggestSkillsAfterHandler: (args) => !args.json,
	},
	args: {
		account: {
			type: "string",
			describe:
				"Show membership information for the given account (id or name).",
		},
		json: {
			type: "boolean",
			describe:
				"Return user information as JSON. Exits with a non-zero status if not authenticated.",
			default: false,
		},
	},
	async handler(args, { config }) {
		await whoami(config, args.account, undefined, args.json);
		metrics.sendMetricsEvent("view accounts", {
			sendMetrics: config.send_metrics,
		});
	},
});

export const authNamespace = createNamespace({
	metadata: {
		description: "🔐 Manage authentication",
		owner: "Workers: Authoring and Testing",
		status: "stable",
		category: "Account",
	},
});

export const authTokenCommand = createCommand({
	metadata: {
		description: "🔑 Retrieve the current authentication token or credentials",
		owner: "Workers: Authoring and Testing",
		status: "stable",
	},
	behaviour: {
		printBanner: (args) => !args.json,
		printConfigWarnings: false,
		suggestSkillsAfterHandler: (args) => !args.json,
	},
	args: {
		json: {
			type: "boolean",
			description: "Return output as JSON with token type information",
			default: false,
		},
	},
	async handler({ json }, { config }) {
		const authFromEnv = getAuthFromEnv();

		let result: AuthTokenInfo;

		if (authFromEnv) {
			if ("apiToken" in authFromEnv) {
				// API token from CLOUDFLARE_API_TOKEN
				result = { type: "api_token", token: authFromEnv.apiToken };
			} else {
				// Global API key + email from CLOUDFLARE_API_KEY + CLOUDFLARE_EMAIL
				result = {
					type: "api_key",
					key: authFromEnv.authKey,
					email: authFromEnv.authEmail,
				};
			}
		} else {
			// OAuth token from local state (wrangler login)
			const token = await getOAuthTokenFromLocalState();
			if (!token) {
				throw new UserError(
					"Not logged in. Please run `wrangler login` to authenticate.",
					{ telemetryMessage: "user auth token not logged in" }
				);
			}
			result = { type: "oauth", token };
		}

		if (json) {
			logger.log(JSON.stringify(result, null, 2));
		} else {
			// For non-JSON output, only output a single token for scripting
			if (result.type === "api_key") {
				throw new UserError(
					"Cannot output a single token when using CLOUDFLARE_API_KEY and CLOUDFLARE_EMAIL.\n" +
						"Use --json to get both key and email, or use CLOUDFLARE_API_TOKEN instead.",
					{
						telemetryMessage: "user auth token unsupported credentials output",
					}
				);
			}
			logger.log(result.token);
		}

		metrics.sendMetricsEvent("retrieve auth token", {
			sendMetrics: config.send_metrics,
		});
	},
});
