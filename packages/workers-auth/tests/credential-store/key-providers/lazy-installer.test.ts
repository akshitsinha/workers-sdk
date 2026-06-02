import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { getGlobalWranglerConfigPath } from "@cloudflare/workers-utils";
import { runInTempDir } from "@cloudflare/workers-utils/test-helpers";
import { afterEach, beforeEach, describe, it } from "vitest";
import {
	findKeyringBinding,
	getKeyringInstallDir,
	installKeyringBindingSync,
	PINNED_KEYRING_VERSION,
	setNpmRunner,
} from "../../../src/credential-store/key-providers/lazy-installer";
import type { SpawnSyncReturns } from "node:child_process";

function mockResult({
	status = 0,
	stdout = "",
	stderr = "",
}: {
	status?: number | null;
	stdout?: string;
	stderr?: string;
} = {}): SpawnSyncReturns<string> {
	return {
		status,
		stdout,
		stderr,
		signal: null,
		output: [null, stdout, stderr],
		pid: 1,
	} as SpawnSyncReturns<string>;
}

describe("lazy keyring installer", () => {
	runInTempDir();
	let lastInvocation: string[] | undefined;

	beforeEach(() => {
		lastInvocation = undefined;
	});

	afterEach(() => {
		setNpmRunner(undefined);
	});

	describe("findKeyringBinding", () => {
		it("returns null when neither the lazy dir nor the global root has the binding", ({
			expect,
		}) => {
			setNpmRunner((args) => {
				lastInvocation = args;
				return mockResult({ stdout: "/nonexistent/global/root\n" });
			});
			expect(findKeyringBinding()).toBeNull();
			expect(lastInvocation).toEqual(["root", "-g"]);
		});

		it("returns the lazy install path when the binding lives there", ({
			expect,
		}) => {
			const dir = path.join(
				getKeyringInstallDir(),
				"node_modules",
				"@napi-rs",
				"keyring"
			);
			mkdirSync(dir, { recursive: true });
			writeFileSync(path.join(dir, "index.js"), "module.exports = {};");
			expect(findKeyringBinding()).toBe(dir);
		});

		it("falls back to the global npm root when the lazy dir is empty", ({
			expect,
		}) => {
			const globalRoot = path.join(
				getGlobalWranglerConfigPath(),
				"global-npm-root"
			);
			const bindingDir = path.join(globalRoot, "@napi-rs", "keyring");
			mkdirSync(bindingDir, { recursive: true });
			writeFileSync(path.join(bindingDir, "index.js"), "module.exports = {};");
			setNpmRunner(() => mockResult({ stdout: globalRoot + "\n" }));
			expect(findKeyringBinding()).toBe(bindingDir);
		});

		it("returns null when `npm root -g` throws (npm not on PATH)", ({
			expect,
		}) => {
			setNpmRunner(() => {
				throw new Error("spawn npm ENOENT");
			});
			expect(findKeyringBinding()).toBeNull();
		});

		it("returns null when `npm root -g` exits non-zero", ({ expect }) => {
			setNpmRunner(() => mockResult({ status: 1 }));
			expect(findKeyringBinding()).toBeNull();
		});
	});

	describe("installKeyringBindingSync", () => {
		it("creates a private host package.json before invoking npm install", ({
			expect,
		}) => {
			setNpmRunner((args) => {
				lastInvocation = args;
				return mockResult({});
			});
			installKeyringBindingSync();
			const hostPkgJson = path.join(getKeyringInstallDir(), "package.json");
			expect(existsSync(hostPkgJson)).toBe(true);
			expect(lastInvocation).toEqual([
				"install",
				`@napi-rs/keyring@${PINNED_KEYRING_VERSION}`,
				"--prefix",
				getKeyringInstallDir(),
				"--no-save",
				"--no-audit",
				"--no-fund",
				"--no-package-lock",
				"--loglevel=error",
			]);
		});

		it("throws a UserError with the npm stderr on non-zero exit", ({
			expect,
		}) => {
			setNpmRunner(() => mockResult({ status: 1, stderr: "404 not found" }));
			expect(() => installKeyringBindingSync()).toThrow(
				/Failed to install `@napi-rs\/keyring` \(npm exited 1\)[\s\S]*404 not found/
			);
		});

		it("throws a UserError when the npm spawn itself fails (npm not on PATH)", ({
			expect,
		}) => {
			setNpmRunner(() => {
				throw new Error("spawn npm ENOENT");
			});
			expect(() => installKeyringBindingSync()).toThrow(
				/Failed to spawn `npm` to install the keyring backend/
			);
		});

		it("does not overwrite an existing host package.json", ({ expect }) => {
			const dir = getKeyringInstallDir();
			mkdirSync(dir, { recursive: true });
			const hostPkgJson = path.join(dir, "package.json");
			writeFileSync(hostPkgJson, '{"customMarker":true}');

			setNpmRunner(() => mockResult({}));
			installKeyringBindingSync();
			expect(readFileSync(hostPkgJson, "utf-8")).toContain("customMarker");
		});
	});
});
