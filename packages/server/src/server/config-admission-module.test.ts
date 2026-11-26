import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { loadConfig } from "./config.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function home(): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), "config-admission-"));
  roots.push(root);
  return root;
}

describe("PASEO_ADMISSION_MODULE", () => {
  test("is read into auth.admissionModule alongside the operator password", async () => {
    const config = loadConfig(await home(), {
      env: { PASEO_PASSWORD: "operator-secret", PASEO_ADMISSION_MODULE: "/opt/provider/index.mjs" },
    });
    expect(config.auth?.admissionModule).toBe("/opt/provider/index.mjs");
    expect(config.auth?.password).toBeTruthy();
  });

  test("is absent when unset, leaving single-user behaviour untouched", async () => {
    const config = loadConfig(await home(), { env: { PASEO_PASSWORD: "operator-secret" } });
    expect(config.auth?.admissionModule).toBeUndefined();
  });

  test("a blank value is ignored", async () => {
    const config = loadConfig(await home(), { env: { PASEO_ADMISSION_MODULE: "   " } });
    expect(config.auth).toBeUndefined();
  });
});
