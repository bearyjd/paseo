import type { DaemonPermission } from "./index.js";

/**
 * Principal admission for multi-user daemons.
 *
 * Without a provider the daemon has one human principal, `owner`, admitted by the shared daemon
 * password or the local credential. With a provider, the shared password stops admitting anyone,
 * and each `hello.auth = { kind: "credential", token }` is resolved to a distinct principal with
 * the permissions the provider grants. The local credential keeps admitting the local operator
 * so the CLI and supervisor still work.
 *
 * The provider is operator-configured code that runs inside the daemon with the daemon's
 * authority, the same trust as a plugin. It is not a plugin subprocess: admission happens
 * before plugins have settled.
 */
export interface AdmissionContext {
  clientId: string;
  remoteAddress?: string;
}

export interface AdmittedPrincipal {
  /** Stable, never `owner`, never a `hub:` or `plugin:` id. */
  principalId: string;
  permissions: readonly DaemonPermission[];
}

export interface AdmissionEvent {
  principalId: string;
  /** `null` revokes the principal: its live sessions are closed and cannot resume. */
  permissions: readonly DaemonPermission[] | null;
}

export interface AdmissionHttpRequest {
  method: string;
  /** Path below `/api/auth`, starting with `/`. */
  path: string;
  /** Lower-cased header names. */
  headers: Record<string, string | undefined>;
  /** Parsed JSON body, or `undefined`. */
  body: unknown;
  remoteAddress?: string;
}

export interface AdmissionHttpResponse {
  status: number;
  body: unknown;
}

export interface AdmissionProvider {
  /** Resolve a credential token. `null` rejects. A throw rejects the connection. */
  authenticate(token: string, context: AdmissionContext): Promise<AdmittedPrincipal | null>;
  /**
   * Provider-hosted HTTP API, served under `/api/auth/*` without the operator password. The
   * provider authenticates each request itself (login, logout, account administration) and owns
   * validation and rate limiting. It runs in the daemon process so the provider is the only
   * writer of its own state; a plugin process must not write that state.
   */
  http?(request: AdmissionHttpRequest): Promise<AdmissionHttpResponse>;
  /** The provider calls the listener when a principal's authority changes or is revoked. */
  subscribe(listener: (event: AdmissionEvent) => void): () => void;
}

const RESERVED_PRINCIPAL_PREFIXES = ["hub:", "plugin:"];

/** A provider must not be able to mint the operator, Hub or plugin principals. */
export function isAssignablePrincipalId(principalId: string): boolean {
  if (principalId.length === 0 || principalId === "owner") return false;
  return !RESERVED_PRINCIPAL_PREFIXES.some((prefix) => principalId.startsWith(prefix));
}
