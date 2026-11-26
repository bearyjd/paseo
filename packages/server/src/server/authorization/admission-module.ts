import path from "node:path";
import { pathToFileURL } from "node:url";
import type { Logger } from "pino";
import type { AdmissionProvider } from "./admission-provider.js";

export interface AdmissionModuleContext {
  paseoHome: string;
  logger: Logger;
}

/**
 * Loads the operator-configured admission provider. The module is trusted code that runs in the
 * daemon, like a plugin; it must be named by an absolute path so nothing is resolved from the
 * working directory. Any failure aborts start-up: falling back to the shared password would
 * silently turn a multi-user deployment into an open one.
 */
export async function loadAdmissionProvider(
  modulePath: string,
  context: AdmissionModuleContext,
): Promise<AdmissionProvider> {
  if (!path.isAbsolute(modulePath)) {
    throw new Error(`Admission module must be an absolute path: ${modulePath}`);
  }
  const loaded = (await import(pathToFileURL(modulePath).href)) as {
    createAdmissionProvider?: (context: AdmissionModuleContext) => unknown;
  };
  if (typeof loaded.createAdmissionProvider !== "function") {
    throw new Error(`Admission module ${modulePath} must export createAdmissionProvider()`);
  }
  const provider = (await loaded.createAdmissionProvider(context)) as Partial<AdmissionProvider>;
  if (typeof provider?.authenticate !== "function" || typeof provider.subscribe !== "function") {
    throw new Error(
      `Admission module ${modulePath} must return an object with authenticate() and subscribe()`,
    );
  }
  return provider as AdmissionProvider;
}
