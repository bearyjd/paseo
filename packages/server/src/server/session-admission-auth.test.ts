import { hashSync } from "bcryptjs";
import { describe, expect, test } from "vitest";
import type { AdmissionProvider } from "./authorization/admission-provider.js";
import { OWNER_PERMISSIONS } from "./authorization/index.js";
import { resolveSessionAdmission } from "./session-admission-auth.js";

const PASSWORD = "shared-daemon-password";
const passwordHash = hashSync(PASSWORD, 4);
const LOCAL = "L".repeat(43);

function providerFor(tokens: Record<string, { principalId: string; permissions: string[] }>) {
  const seen: Array<{ token: string; clientId: string }> = [];
  const provider: AdmissionProvider = {
    async authenticate(token, context) {
      seen.push({ token, clientId: context.clientId });
      const entry = tokens[token];
      return entry
        ? { principalId: entry.principalId, permissions: entry.permissions as never }
        : null;
    },
    subscribe: () => () => undefined,
  };
  return { provider, seen };
}

describe("resolveSessionAdmission without a provider (unchanged behaviour)", () => {
  test("no password configured admits the owner", async () => {
    const result = await resolveSessionAdmission({
      credential: undefined,
      passwordHash: undefined,
      localCredential: null,
    });
    expect(result).toEqual({ admission: { principalId: "owner", permissions: OWNER_PERMISSIONS } });
  });

  test("the daemon password admits the owner and a wrong one is rejected", async () => {
    const ok = await resolveSessionAdmission({
      credential: { kind: "password", password: PASSWORD },
      passwordHash,
      localCredential: null,
    });
    expect(ok).toMatchObject({ admission: { principalId: "owner" } });
    const bad = await resolveSessionAdmission({
      credential: { kind: "password", password: "nope" },
      passwordHash,
      localCredential: null,
    });
    expect(bad).toEqual({ rejection: "incorrect_password" });
  });

  test("a credential hello is rejected when no provider is configured", async () => {
    const result = await resolveSessionAdmission({
      credential: { kind: "credential", token: "x" },
      passwordHash,
      localCredential: null,
    });
    expect(result).toEqual({ rejection: "incorrect_password" });
  });
});

describe("resolveSessionAdmission with an admission provider", () => {
  const { provider } = providerFor({
    "good-token": { principalId: "user:alice", permissions: ["workspace.read"] },
  });
  const base = { passwordHash, localCredential: LOCAL, provider, clientId: "c1" } as const;

  test("a provider-recognised credential admits that principal with exactly its permissions", async () => {
    const result = await resolveSessionAdmission({
      ...base,
      credential: { kind: "credential", token: "good-token" },
    });
    expect(result).toEqual({
      admission: { principalId: "user:alice", permissions: ["workspace.read"] },
    });
  });

  test("an unrecognised credential is rejected", async () => {
    const result = await resolveSessionAdmission({
      ...base,
      credential: { kind: "credential", token: "bad" },
    });
    expect(result).toEqual({ rejection: "incorrect_password" });
  });

  test("the shared daemon password no longer admits anyone", async () => {
    const result = await resolveSessionAdmission({
      ...base,
      credential: { kind: "password", password: PASSWORD },
    });
    expect(result).toEqual({ rejection: "incorrect_password" });
  });

  test("no credential is rejected, never admitted as owner, even with no daemon password", async () => {
    expect(await resolveSessionAdmission({ ...base, credential: undefined })).toEqual({
      rejection: "password_required",
    });
    expect(
      await resolveSessionAdmission({ ...base, passwordHash: undefined, credential: undefined }),
    ).toEqual({ rejection: "password_required" });
  });

  test("the local credential still admits the local operator", async () => {
    const result = await resolveSessionAdmission({
      ...base,
      credential: { kind: "localCredential", token: LOCAL },
    });
    expect(result).toMatchObject({ admission: { principalId: "owner" } });
    const wrong = await resolveSessionAdmission({
      ...base,
      credential: { kind: "localCredential", token: "W".repeat(43) },
    });
    expect(wrong).toEqual({ rejection: "incorrect_password" });
  });

  test("a provider that throws rejects instead of admitting", async () => {
    const throwing: AdmissionProvider = {
      authenticate: async () => {
        throw new Error("store down");
      },
      subscribe: () => () => undefined,
    };
    await expect(
      resolveSessionAdmission({
        ...base,
        provider: throwing,
        credential: { kind: "credential", token: "x" },
      }),
    ).rejects.toThrow("store down");
  });

  test("a provider may not return the owner principal id or an unknown permission", async () => {
    const hijack: AdmissionProvider = {
      authenticate: async () => ({ principalId: "owner", permissions: ["workspace.read"] }),
      subscribe: () => () => undefined,
    };
    const result = await resolveSessionAdmission({
      ...base,
      provider: hijack,
      credential: { kind: "credential", token: "x" },
    });
    expect(result).toEqual({ rejection: "incorrect_password" });
    const bogus: AdmissionProvider = {
      authenticate: async () => ({
        principalId: "user:x",
        permissions: ["root.everything"] as never,
      }),
      subscribe: () => () => undefined,
    };
    expect(
      await resolveSessionAdmission({
        ...base,
        provider: bogus,
        credential: { kind: "credential", token: "x" },
      }),
    ).toEqual({ rejection: "incorrect_password" });
  });
});
