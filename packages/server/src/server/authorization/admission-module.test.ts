import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import pino from "pino";
import { afterEach, describe, expect, test } from "vitest";
import { loadAdmissionProvider } from "./admission-module.js";

const roots: string[] = [];
const logger = pino({ level: "silent" });

async function moduleWith(source: string): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), "admission-module-"));
  roots.push(root);
  const file = path.join(root, "provider.mjs");
  await writeFile(file, source);
  return file;
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("loadAdmissionProvider", () => {
  test("loads createAdmissionProvider and passes the paseo home and logger", async () => {
    const file = await moduleWith(`
      export function createAdmissionProvider(context) {
        return {
          authenticate: async (token) => ({ principalId: "user:" + token, permissions: [] }),
          subscribe: () => () => undefined,
          home: context.paseoHome,
          hasLogger: typeof context.logger.info === "function",
        };
      }`);
    const provider = await loadAdmissionProvider(file, { paseoHome: "/tmp/home", logger });
    expect(provider).toMatchObject({ home: "/tmp/home", hasLogger: true });
    expect(await provider.authenticate("x", { clientId: "c" })).toEqual({
      principalId: "user:x",
      permissions: [],
    });
  });

  test("accepts an async factory", async () => {
    const file = await moduleWith(`
      export async function createAdmissionProvider() {
        return { authenticate: async () => null, subscribe: () => () => undefined };
      }`);
    await expect(loadAdmissionProvider(file, { paseoHome: "/h", logger })).resolves.toBeDefined();
  });

  test("rejects a relative path so the module cannot be resolved from the working directory", async () => {
    await expect(
      loadAdmissionProvider("./provider.mjs", { paseoHome: "/h", logger }),
    ).rejects.toThrow(/absolute/i);
  });

  test("rejects a missing module, a missing export and a malformed provider", async () => {
    await expect(
      loadAdmissionProvider("/nonexistent/provider.mjs", { paseoHome: "/h", logger }),
    ).rejects.toThrow();
    const noExport = await moduleWith("export const other = 1;");
    await expect(loadAdmissionProvider(noExport, { paseoHome: "/h", logger })).rejects.toThrow(
      /createAdmissionProvider/,
    );
    const malformed = await moduleWith("export function createAdmissionProvider() { return {}; }");
    await expect(loadAdmissionProvider(malformed, { paseoHome: "/h", logger })).rejects.toThrow(
      /authenticate/,
    );
  });
});
