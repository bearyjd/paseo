import { compare } from "bcryptjs";
import type { WSHelloMessage } from "@getpaseo/protocol/messages";
import { isAssignablePrincipalId, type AdmissionProvider } from "./authorization/admission-provider.js";
import { OWNER_PERMISSIONS, isDaemonPermission } from "./authorization/index.js";
import { matchesLocalCredential } from "./local-credential.js";
import type { SessionAdmission } from "./websocket-server.js";

export type AdmissionFailure = "password_required" | "incorrect_password";

type AdmissionResolution = { admission: SessionAdmission } | { rejection: AdmissionFailure };

const OWNER_ADMISSION: SessionAdmission = { principalId: "owner", permissions: OWNER_PERMISSIONS };

export async function resolveSessionAdmission(input: {
  credential: WSHelloMessage["auth"];
  passwordHash: string | undefined;
  localCredential: string | null;
  provider?: AdmissionProvider;
  clientId?: string;
  remoteAddress?: string;
}): Promise<AdmissionResolution> {
  const { credential, passwordHash, localCredential, provider } = input;
  if (provider) return resolveProviderAdmission({ ...input, provider });
  if (!passwordHash) {
    return { admission: OWNER_ADMISSION };
  }
  if (!credential) {
    return { rejection: "password_required" };
  }
  if (credential.kind === "localCredential") {
    if (localCredential && matchesLocalCredential(localCredential, credential.token)) {
      return { admission: OWNER_ADMISSION };
    }
    return { rejection: "incorrect_password" };
  }
  if (credential.kind !== "password") {
    return { rejection: "incorrect_password" };
  }
  return (await compare(credential.password, passwordHash))
    ? { admission: OWNER_ADMISSION }
    : { rejection: "incorrect_password" };
}

/**
 * Provider mode never falls through to an open owner session: with or without a daemon password,
 * a connection with no credential is rejected, and the shared password admits nobody.
 */
async function resolveProviderAdmission(input: {
  credential: WSHelloMessage["auth"];
  localCredential: string | null;
  provider: AdmissionProvider;
  clientId?: string;
  remoteAddress?: string;
}): Promise<AdmissionResolution> {
  const { credential, localCredential, provider } = input;
  if (!credential) return { rejection: "password_required" };
  if (credential.kind === "localCredential") {
    return localCredential && matchesLocalCredential(localCredential, credential.token)
      ? { admission: OWNER_ADMISSION }
      : { rejection: "incorrect_password" };
  }
  if (credential.kind !== "credential") return { rejection: "incorrect_password" };

  const admitted = await provider.authenticate(credential.token, {
    clientId: input.clientId ?? "",
    ...(input.remoteAddress ? { remoteAddress: input.remoteAddress } : {}),
  });
  if (!admitted || !isAssignablePrincipalId(admitted.principalId)) {
    return { rejection: "incorrect_password" };
  }
  if (!admitted.permissions.every((permission) => isDaemonPermission(permission))) {
    return { rejection: "incorrect_password" };
  }
  return {
    admission: { principalId: admitted.principalId, permissions: [...new Set(admitted.permissions)] },
  };
}
