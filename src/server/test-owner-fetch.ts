import { existsSync, readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

/**
 * Act as the studio owner in an integration test.
 *
 * The host no longer treats "connected over 127.0.0.1" as proof of ownership,
 * because every local process — including anything the agent's browser opens —
 * also connects from loopback. The owner's credential is the token file in the
 * data home, which only the owner's OS account can read. Tests that drive the
 * real host over HTTP are ordinary clients, so they authenticate the same way:
 * by sending that token.
 *
 * The token is read lazily on each request so calling this before the fixture
 * host has written its data home still works.
 */
export function authenticateAsOwner(dataDir: string): void {
  const original = globalThis.fetch;
  const tokenFile = path.join(dataDir, "access.token");

  const ownerToken = (): string | null => {
    try {
      if (!existsSync(tokenFile)) return null;
      const token = readFileSync(tokenFile, "utf8").trim();
      return token || null;
    } catch {
      return null;
    }
  };

  globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;

    // Only the studio API needs the credential; leave other URLs untouched.
    if (!/\/api\//.test(url)) return original(input, init);

    const existing = new Headers(
      init?.headers ?? (input instanceof Request ? input.headers : undefined),
    );
    // Tests that assert an unauthenticated request is refused must stay
    // unauthenticated; mark such requests explicitly.
    if (existing.has("x-test-no-owner-auth")) {
      existing.delete("x-test-no-owner-auth");
      return original(input, { ...init, headers: existing });
    }
    if (!existing.has("authorization")) {
      const token = ownerToken();
      if (token) existing.set("authorization", `Bearer ${token}`);
    }
    return original(input, { ...init, headers: existing });
  }) as typeof fetch;
}

/** The default data home, for tests that do not build an isolated one. */
export function defaultDataDir(): string {
  return process.env.OPENBOT_DATA_DIR || path.join(os.homedir(), ".openbot");
}
