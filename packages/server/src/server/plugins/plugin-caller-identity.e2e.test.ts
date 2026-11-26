import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { hash } from "bcryptjs";
import { WebSocket } from "ws";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { DaemonClient } from "../test-utils/daemon-client.js";
import { createTestPaseoDaemon } from "../test-utils/paseo-daemon.js";
import { resolveDaemonVersion } from "../daemon-version.js";
import type { AdmissionProvider, AdmittedPrincipal } from "../authorization/admission-provider.js";

const roots: string[] = [];
const originalEnv = { ...process.env };

beforeEach(() => {
  vi.useRealTimers();
  process.env = { ...originalEnv, PASEO_SUPERVISED: "0" };
});
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

type Frame = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const PLUGIN = `import { defineRpc, defineSubscription } from "@getpaseo/plugin";
import { type PluginServerContext } from "@getpaseo/plugin/server";
import { z } from "zod";

const callerShape = z.object({ principalId: z.string(), permissions: z.array(z.string()) }).nullable();
const whoami = defineRpc({
  name: "whoami",
  // The input is attacker-controlled; the handler must not be able to confuse it with the caller.
  input: z.object({ caller: z.unknown().optional() }),
  output: z.object({ caller: callerShape, claimed: z.unknown() }),
});
const watch = defineSubscription({ name: "watch", input: z.object({}), event: z.object({ caller: callerShape }) });

export default function contribute(server: PluginServerContext) {
  server.handle(whoami, (input, context) => ({ caller: context.caller ?? null, claimed: input.caller ?? null }));
  server.handle(watch, async (_input, context) => {
    await context.push({ caller: context.caller ?? null });
  });
  return () => undefined;
}`;

function provider(tokens: Record<string, AdmittedPrincipal>): AdmissionProvider {
  return {
    authenticate: async (token) => tokens[token] ?? null,
    subscribe: () => () => undefined,
  };
}

async function startWithPlugin(tokens: Record<string, AdmittedPrincipal>) {
  const dir = await mkdtemp(path.join(tmpdir(), "caller-identity-plugin-"));
  roots.push(dir);
  await writeFile(
    path.join(dir, "paseo-plugin.json"),
    JSON.stringify({
      id: "who",
      requirements: { paseo: `>=${resolveDaemonVersion(import.meta.url)}` },
    }),
  );
  await writeFile(path.join(dir, "index.server.ts"), PLUGIN);
  const daemon = await createTestPaseoDaemon({
    auth: { password: await hash("operator-password", 4), admissionProvider: provider(tokens) },
  });
  // The operator uses the local credential, which provider mode keeps working.
  const operator = new DaemonClient({
    url: `ws://127.0.0.1:${daemon.port}/ws`,
    appVersion: "0.4.0",
    localCredential: async () =>
      (await readFile(path.join(daemon.paseoHome, "local-credential"), "utf8")).trim(),
  });
  await operator.connect();
  await operator.patchDaemonConfig({ pluginsEnabled: true });
  await operator.installDirectoryPlugin(dir);
  return { daemon, operator };
}

async function userSession(port: number, token: string) {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`);
  const frames: Frame[] = [];
  ws.on("message", (raw) => frames.push(JSON.parse(raw.toString())));
  await new Promise<void>((resolve, reject) => {
    ws.once("open", () => resolve());
    ws.once("error", reject);
  });
  ws.send(
    JSON.stringify({
      type: "hello",
      clientId: `c-${token}`,
      clientType: "cli",
      protocolVersion: 1,
      auth: { kind: "credential", token },
    }),
  );
  const wait = async <T>(read: () => T | undefined): Promise<T> => {
    const end = Date.now() + 8000;
    for (;;) {
      const v = read();
      if (v !== undefined) return v;
      if (Date.now() > end) throw new Error("timeout");
      await new Promise((r) => setTimeout(r, 20));
    }
  };
  await wait(() => frames.find((f) => f.message?.payload?.status === "server_info"));
  const request = async (message: Frame) => {
    const requestId = `req-${Math.random().toString(36).slice(2)}`;
    ws.send(JSON.stringify({ type: "session", message: { ...message, requestId } }));
    return wait(() => frames.find((f) => f.message?.payload?.requestId === requestId)?.message);
  };
  return { ws, frames, request, wait };
}

test("plugin handlers receive the authenticated caller, never one claimed in the input", async () => {
  const { daemon, operator } = await startWithPlugin({
    "tok-admin": { principalId: "user:admin", permissions: ["daemon.read", "daemon.manage"] },
    "tok-dev": { principalId: "user:dev", permissions: ["daemon.read", "workspace.read"] },
  });
  try {
    const owner = (await operator.invokePluginRpc("who", "whoami", {})) as {
      caller: { principalId: string; permissions: string[] };
    };
    expect(owner.caller.principalId).toBe("owner");
    expect(owner.caller.permissions).toContain("daemon.manage");

    const admin = await userSession(daemon.port, "tok-admin");
    const spoof = await admin.request({
      type: "plugin.rpc.invoke.request",
      pluginId: "who",
      method: "whoami",
      input: { caller: { principalId: "owner", permissions: ["daemon.manage"] } },
    });
    expect(spoof.type).toBe("plugin.rpc.invoke.response");
    expect(spoof.payload.output.caller).toEqual({
      principalId: "user:admin",
      permissions: ["daemon.read", "daemon.manage"],
    });
    expect(spoof.payload.output.claimed).toEqual({
      principalId: "owner",
      permissions: ["daemon.manage"],
    });

    // The existing gate still keeps non-operators out of plugin RPC entirely.
    const dev = await userSession(daemon.port, "tok-dev");
    const denied = await dev.request({
      type: "plugin.rpc.invoke.request",
      pluginId: "who",
      method: "whoami",
      input: {},
    });
    expect(denied).toMatchObject({ type: "rpc_error", payload: { code: "access_denied" } });
    admin.ws.close();
    dev.ws.close();
  } finally {
    await operator.close();
    await daemon.close();
  }
});

test("subscription handlers receive the caller too", async () => {
  const { daemon, operator } = await startWithPlugin({
    "tok-admin": { principalId: "user:admin", permissions: ["daemon.read", "daemon.manage"] },
  });
  try {
    const admin = await userSession(daemon.port, "tok-admin");
    const subscribed = await admin.request({
      type: "plugin.rpc.subscribe.request",
      pluginId: "who",
      method: "watch",
      input: {},
    });
    expect(subscribed.type).toBe("plugin.rpc.subscribe.response");
    const event = await admin.wait(
      () => admin.frames.find((f) => f.message?.type === "plugin.rpc.event")?.message,
    );
    expect(event.payload.event.caller).toEqual({
      principalId: "user:admin",
      permissions: ["daemon.read", "daemon.manage"],
    });
    admin.ws.close();
  } finally {
    await operator.close();
    await daemon.close();
  }
});
