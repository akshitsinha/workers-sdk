import { UserError } from "@cloudflare/workers-utils";
import { getCloudflareAuthUseKeyringFromEnv } from "../env-vars";
import { EncryptedFileCredentialStore } from "./encrypted-file-store";
import { FileCredentialStore } from "./file-store";
import { resolveKeyProvider } from "./key-providers/factory";
import { PINNED_KEYRING_VERSION } from "./key-providers/lazy-installer";
import { getResolverSessionFlags } from "./state";
import type { AuthConfigStorage } from "../config-file/auth";
import type { OAuthFlowLogger } from "../context";
import type { CredentialStore } from "./interface";

/**
 * Per-consumer configuration for the credential-storage resolver.
 *
 * Captured by {@link createCredentialStorageContext} in a closure so the
 * returned `storage` adapter and `getActiveStore` function can both
 * re-resolve the active store on every call without re-reading shared
 * mutable module state.
 */
export interface CredentialStorageContext {
	/**
	 * Keyring service identifier (e.g. `"wrangler"`). Becomes the `-s`
	 * argument to `/usr/bin/security`, the `service` attribute for
	 * `secret-tool`, and the `service` argument to `@napi-rs/keyring`'s
	 * `Entry`. Must be non-empty.
	 */
	serviceName: string;

	/**
	 * Whether the user has opted into keyring storage. Consulted on every
	 * credential read/write so runtime preference changes (e.g. a user
	 * toggling the option mid-session) take effect.
	 */
	isKeyringEnabled: () => boolean;

	/** Drop-in replacement for the consumer's logger singleton. */
	logger: OAuthFlowLogger;

	/** Whether the process should not prompt the user. */
	isNonInteractiveOrCI: () => boolean;

	/**
	 * Consumer's CLI name for error-message templating, e.g. `"wrangler"`.
	 * Used in hints like ``Run `<cliName> login --use-keyring` …``.
	 * Defaults to `"your CLI"` when omitted.
	 */
	cliName?: string;
}

/**
 * Bundle returned by {@link createCredentialStorageContext}.
 *
 * - `storage`: an {@link AuthConfigStorage} adapter that delegates to the
 *   active {@link CredentialStore} on every method call. Pass this as
 *   `ctx.storage` to {@link createOAuthFlow}.
 * - `getActiveStore`: the live `CredentialStore` lookup, suitable for
 *   `whoami`-style consumers that want to call `describe()`.
 *
 * The same `storage` and `getActiveStore` are wired against the same
 * closure, so a runtime preference flip (e.g. `wrangler login
 * --no-use-keyring`) is observable through both surfaces on the very
 * next call.
 */
export interface CredentialStorageBundle {
	storage: AuthConfigStorage;
	getActiveStore: () => CredentialStore;
}

/**
 * Build a credential-storage bundle for a consumer (wrangler, future
 * Cloudflare CLIs).
 *
 * The bundle's `storage` is an `AuthConfigStorage` that re-resolves the
 * underlying store on every read/write/clear/path call. Selection order
 * (highest precedence first):
 *
 *   1. `CLOUDFLARE_AUTH_USE_KEYRING=false` env var — forces the file store.
 *   2. `CLOUDFLARE_AUTH_USE_KEYRING=true` env var — forces keyring storage;
 *      failures throw rather than soft-falling-back.
 *   3. `isKeyringEnabled()` callback (the consumer's persistent preference) —
 *      uses keyring storage; failures soft-fall-back with a one-time warning.
 *   4. Otherwise — defaults to the plaintext file store.
 *
 * The env var and the `isKeyringEnabled` callback are re-read on every
 * call so runtime preference changes take effect without rebuilding the
 * storage layer.
 */
export function createCredentialStorageContext(
	context: CredentialStorageContext
): CredentialStorageBundle {
	const config = {
		...context,
		cliName: context.cliName ?? "your CLI",
	};

	function getActiveStore(): CredentialStore {
		return resolveActiveCredentialStore(config);
	}

	const storage: AuthConfigStorage = {
		read: () => getActiveStore().read(),
		write: (value) => getActiveStore().write(value),
		clear: () => getActiveStore().clear(),
		path: () => getActiveStore().path(),
	};

	return { storage, getActiveStore };
}

type ResolvedConfig = Required<CredentialStorageContext>;

function resolveActiveCredentialStore(config: ResolvedConfig): CredentialStore {
	const envOverride = getCloudflareAuthUseKeyringFromEnv();

	if (envOverride === false) {
		return new FileCredentialStore();
	}

	const forced = envOverride === true;
	const wantsKeyring = envOverride ?? config.isKeyringEnabled() ?? false;

	if (!wantsKeyring) {
		return new FileCredentialStore();
	}

	const resolution = resolveKeyProvider(config.serviceName);

	switch (resolution.kind) {
		case "available":
			return new EncryptedFileCredentialStore(resolution.provider, (result) => {
				config.logger.log(
					`Migrated credentials from ${result.legacyPath} into ${result.encryptedPath} (key in ${result.keyProviderDescription}).`
				);
			});

		case "needs-install":
			return handleNeedsInstall(resolution, forced, config);

		case "unsupported":
			return handleUnsupported(forced, config);
	}
}

function handleNeedsInstall(
	resolution: Extract<
		ReturnType<typeof resolveKeyProvider>,
		{ kind: "needs-install" }
	>,
	forced: boolean,
	config: ResolvedConfig
): CredentialStore {
	const flags = getResolverSessionFlags();

	if (flags.installFailedThisSession) {
		if (forced) {
			throw new UserError(
				`CLOUDFLARE_AUTH_USE_KEYRING is set but the keyring backend could not be installed earlier this session.`,
				{ telemetryMessage: "workers-auth keyring install previously failed" }
			);
		}
		return fallbackToFileWithWarning(
			`The keyring backend could not be installed earlier this session; using the plaintext credentials file.`,
			config
		);
	}

	if (config.isNonInteractiveOrCI()) {
		throw new UserError(windowsBindingMissingMessage(config.cliName), {
			telemetryMessage: "workers-auth keyring binding not installed",
		});
	}

	try {
		config.logger.log(`🔐 Installing keyring backend (one-time, ~2 MB)…`);
		resolution.install();
	} catch (e) {
		flags.installFailedThisSession = true;
		if (forced) {
			throw e instanceof UserError
				? e
				: new UserError(
						`Failed to install the keyring backend: ${e instanceof Error ? e.message : String(e)}`,
						{ telemetryMessage: "workers-auth keyring install threw" }
					);
		}
		return fallbackToFileWithWarning(
			`Failed to install the keyring backend (${e instanceof Error ? e.message : String(e)}); falling back to the plaintext credentials file.`,
			config
		);
	}

	return new EncryptedFileCredentialStore(
		resolution.afterInstall(),
		(result) => {
			config.logger.log(
				`Migrated credentials from ${result.legacyPath} into ${result.encryptedPath} (key in ${result.keyProviderDescription}).`
			);
		}
	);
}

function handleUnsupported(
	forced: boolean,
	config: ResolvedConfig
): CredentialStore {
	const platform = process.platform;

	// Linux without `secret-tool` lands here. macOS and Windows have
	// keyring backends, so this branch covers Linux-missing-tool and
	// genuinely unsupported platforms (FreeBSD, etc.).
	const linuxMissingTool = platform === "linux";
	const message = linuxMissingTool
		? secretToolMissingMessage(config.cliName)
		: `OS keyring storage is not supported on \`${platform}\`; falling back to the plaintext credentials file.`;

	if (forced) {
		throw new UserError(
			linuxMissingTool
				? `CLOUDFLARE_AUTH_USE_KEYRING is set but ${message}`
				: `CLOUDFLARE_AUTH_USE_KEYRING is set but no keyring backend is available on \`${platform}\`.`,
			{
				telemetryMessage: linuxMissingTool
					? "workers-auth keyring secret tool missing"
					: "workers-auth keyring unsupported platform",
			}
		);
	}

	if (linuxMissingTool && config.isNonInteractiveOrCI()) {
		throw new UserError(message, {
			telemetryMessage: "workers-auth keyring secret tool missing",
		});
	}

	const flags = getResolverSessionFlags();
	if (linuxMissingTool) {
		if (!flags.hasWarnedAboutSecretToolMissing) {
			flags.hasWarnedAboutSecretToolMissing = true;
			config.logger.warn(
				`${message}\n\nFalling back to the plaintext credentials file for this session.`
			);
		}
		return new FileCredentialStore();
	}

	return fallbackToFileWithWarning(message, config);
}

function fallbackToFileWithWarning(
	message: string,
	config: ResolvedConfig
): CredentialStore {
	const flags = getResolverSessionFlags();
	if (!flags.hasWarnedAboutKeyringFallback) {
		flags.hasWarnedAboutKeyringFallback = true;
		config.logger.warn(message);
	}
	return new FileCredentialStore();
}

function secretToolMissingMessage(cliName: string): string {
	return `\`secret-tool\` is required for OS keyring storage on Linux but is not installed.

Install it via your package manager:
  Debian/Ubuntu:  sudo apt-get install libsecret-tools
  Fedora/RHEL:    sudo dnf install libsecret
  Arch:           sudo pacman -S libsecret
  Alpine:         apk add libsecret

Or disable keyring storage: \`${cliName} login --no-use-keyring\`.`;
}

function windowsBindingMissingMessage(cliName: string): string {
	return `\`@napi-rs/keyring\` is required for OS keyring storage on Windows but is not installed.

Run \`${cliName} login --use-keyring\` interactively to install it automatically, or install it globally for CI:

  npm install -g @napi-rs/keyring@${PINNED_KEYRING_VERSION}

Or disable keyring storage: \`${cliName} login --no-use-keyring\`.`;
}
