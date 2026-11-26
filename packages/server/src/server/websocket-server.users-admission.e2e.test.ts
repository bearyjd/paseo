import { WebSocket } from "ws";
import { hash } from "bcryptjs";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { createTestPaseoDaemon } from "./test-utils/paseo-daemon.js";
import type {
  AdmissionEvent,
  AdmissionProvider,
  AdmittedPrincipal,
} from "./authorization/admission-provider.js";

const originalEnv = { ...process.env };
const DAEMON_PASSWORD = "operator-only-password";

class FakeProvider implements AdmissionProvider {
  readonly tokens = new Map<string, AdmittedPrincipal>();
  private listeners = new Set<(event: AdmissionEvent) => void>();
  readonly seen: Array<{ token: string; clientId: string }> = [];
  login: AdmissionProvider["login"] = async (body) => ({ status: 200, body: { echoed: body } });
  async authenticate(token: string, context: { clientId: string }) {
    this.seen.push({ token, clientId: context.clientId });
    return this.tokens.get(token) ?? null;
  }
  subscribe(listener: (event: AdmissionEvent) => void) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
  emit(event: AdmissionEvent) {
    for (const listener of this.listeners) listener(event);
  }
}

type Frame = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

async function start(provider: AdmissionProvider) {
  return createTestPaseoDaemon({
    auth: { password: await hash(DAEMON_PASSWORD, 4), admissionProvider: provider },
  });
}

function open(port: number, headers?: Record<string, string>) {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`, { headers });
  const frames: Frame[] = [];
  const closed = new Promise<{ code: number; reason: string }>((resolve) =>
    ws.once("close", (code, reason) => resolve({ code, reason: reason.toString() })),
  );
  ws.on("message", (raw) => frames.push(JSON.parse(raw.toString())));
  const opened = new Promise<void>((resolve, reject) => {
    ws.once("open", () => resolve());
    ws.once("error", reject);
  });
  return { ws, frames, closed, opened };
}

function hello(clientId: string, auth?: Frame) {
  return {
    type: "hello",
    clientId,
    clientType: "cli",
    protocolVersion: 1,
    capabilities: { hello_rejection: true },
    ...(auth ? { auth } : {}),
  };
}

async function waitFor<T>(read: () => T | undefined, label: string): Promise<T> {
  const deadline = Date.now() + 5000;
  for (;;) {
    const value = read();
    if (value !== undefined) return value;
    if (Date.now() > deadline) throw new Error(`timed out: ${label}`);
    await new Promise((r) => setTimeout(r, 20));
  }
}

const serverInfo = (frames: Frame[]) =>
  frames.find((f) => f.type === "session" && f.message?.payload?.status === "server_info")?.message.payload;
const rejection = (frames: Frame[]) => frames.find((f) => f.type === "hello.rejected");

async function admit(port: number, clientId: string, auth?: Frame) {
  const c = open(port);
  await c.opened;
  c.ws.send(JSON.stringify(hello(clientId, auth)));
  await waitFor(() => (serverInfo(c.frames) || rejection(c.frames) ? true : undefined), "hello result");
  return c;
}

describe("daemon with an admission provider", () => {
  beforeEach(() => {
    vi.useRealTimers();
    process.env = { ...originalEnv, PASEO_SUPERVISED: "0" };
  });

  test("admits each credential as its own principal with exactly its permissions", async () => {
    const provider = new FakeProvider();
    provider.tokens.set("tok-alice", { principalId: "user:alice", permissions: ["daemon.read", "workspace.read"] });
    provider.tokens.set("tok-admin", { principalId: "user:admin", permissions: ["daemon.read", "daemon.manage", "workspace.read"] });
    const daemon = await start(provider);
    try {
      const alice = await admit(daemon.port, "same-client-id", { kind: "credential", token: "tok-alice" });
      const admin = await admit(daemon.port, "same-client-id", { kind: "credential", token: "tok-admin" });
      expect([...serverInfo(alice.frames).permissions].sort()).toEqual(["daemon.read", "workspace.read"]);
      expect([...serverInfo(admin.frames).permissions].sort()).toEqual(["daemon.manage", "daemon.read", "workspace.read"]);
      expect(serverInfo(alice.frames).features).toMatchObject({ principalAdmission: true, pluginCallerIdentity: true });
      // Alice cannot reach an operator-only operation even though she shares a clientId with the admin.
      alice.ws.send(JSON.stringify({ type: "session", message: { type: "plugin.list.request", requestId: "r1" } }));
      const denied = await waitFor(
        () => alice.frames.find((f) => f.message?.type === "rpc_error" && f.message.payload.requestId === "r1"),
        "alice denied",
      );
      expect(denied.message.payload.code).toBe("access_denied");
      alice.ws.close();
      admin.ws.close();
    } finally {
      await daemon.close();
    }
  });

  test("rejects the shared daemon password, a bad token and a missing credential", async () => {
    const provider = new FakeProvider();
    const daemon = await start(provider);
    try {
      const shared = await admit(daemon.port, "c1", { kind: "password", password: DAEMON_PASSWORD });
      expect(serverInfo(shared.frames)).toBeUndefined();
      expect(rejection(shared.frames)).toMatchObject({ reason: "incorrect_password", authMode: "users" });
      const bad = await admit(daemon.port, "c2", { kind: "credential", token: "nope" });
      expect(rejection(bad.frames)).toMatchObject({ reason: "incorrect_password" });
      const none = await admit(daemon.port, "c3");
      expect(rejection(none.frames)).toMatchObject({ reason: "password_required", authMode: "users" });
      expect(serverInfo(none.frames)).toBeUndefined();
    } finally {
      await daemon.close();
    }
  });

  test("the header bearer path goes through the provider, not the shared password", async () => {
    const provider = new FakeProvider();
    provider.tokens.set("tok-alice", { principalId: "user:alice", permissions: ["workspace.read"] });
    const daemon = await start(provider);
    try {
      const withPassword = open(daemon.port, { Authorization: `Bearer ${DAEMON_PASSWORD}` });
      await withPassword.opened.catch(() => undefined);
      expect(await withPassword.closed).toMatchObject({ code: 4401 });

      const withToken = open(daemon.port, { Authorization: "Bearer tok-alice" });
      await withToken.opened;
      withToken.ws.send(JSON.stringify(hello("hdr")));
      await waitFor(() => serverInfo(withToken.frames), "header admission");
      expect(serverInfo(withToken.frames).permissions).toEqual(["workspace.read"]);
      withToken.ws.close();
    } finally {
      await daemon.close();
    }
  });

  test("revoking a principal closes its live sockets, and it cannot reconnect", async () => {
    const provider = new FakeProvider();
    provider.tokens.set("tok-alice", { principalId: "user:alice", permissions: ["workspace.read"] });
    const daemon = await start(provider);
    try {
      const alice = await admit(daemon.port, "a1", { kind: "credential", token: "tok-alice" });
      expect(serverInfo(alice.frames)).toBeDefined();
      provider.tokens.delete("tok-alice");
      provider.emit({ principalId: "user:alice", permissions: null });
      await alice.closed;
      const again = await admit(daemon.port, "a1", { kind: "credential", token: "tok-alice" });
      expect(rejection(again.frames)).toBeDefined();
    } finally {
      await daemon.close();
    }
  });

  test("narrowing a principal's permissions applies to its live session immediately", async () => {
    const provider = new FakeProvider();
    provider.tokens.set("tok-admin", { principalId: "user:admin", permissions: ["daemon.read", "daemon.manage"] });
    const daemon = await start(provider);
    try {
      const admin = await admit(daemon.port, "m1", { kind: "credential", token: "tok-admin" });
      const ask = async (id: string) => {
        admin.ws.send(JSON.stringify({ type: "session", message: { type: "plugin.list.request", requestId: id } }));
        return waitFor(() => admin.frames.find((f) => f.message?.payload?.requestId === id)?.message, id);
      };
      expect((await ask("before")).type).toBe("plugin.list.response");
      provider.emit({ principalId: "user:admin", permissions: ["daemon.read"] });
      await new Promise((r) => setTimeout(r, 50));
      expect(await ask("after")).toMatchObject({ type: "rpc_error", payload: { code: "access_denied" } });
      admin.ws.close();
    } finally {
      await daemon.close();
    }
  });

  test("POST /api/auth/login is reachable without the daemon password and delegates to the provider", async () => {
    const provider = new FakeProvider();
    const daemon = await start(provider);
    try {
      const response = await fetch(`http://127.0.0.1:${daemon.port}/api/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "u" }),
      });
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ echoed: { username: "u" } });
      // Everything else on /api still needs the operator password.
      expect((await fetch(`http://127.0.0.1:${daemon.port}/api/status`)).status).toBe(401);
    } finally {
      await daemon.close();
    }
  });

  test("without a provider the login route does not exist", async () => {
    const daemon = await createTestPaseoDaemon({ auth: { password: await hash(DAEMON_PASSWORD, 4) } });
    try {
      const response = await fetch(`http://127.0.0.1:${daemon.port}/api/auth/login`, { method: "POST" });
      expect(response.status).toBe(401);
    } finally {
      await daemon.close();
    }
  });

  test("refuses to start in provider mode without an operator password (HTTP and MCP would be open)", async () => {
    await expect(createTestPaseoDaemon({ auth: { admissionProvider: new FakeProvider() } })).rejects.toThrow(
      /admission provider requires/i,
    );
  });
});
