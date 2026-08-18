import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey, type JWTPayload } from "jose";
import type { NextFunction, Request, Response } from "express";
import { parseActiveTenantIds, type TenantAuthContext } from "./auth";

type OidcConfig = {
  issuer: string;
  audience: string;
  jwksUrl: string;
  tenantClaim: string;
  requiredScope: string;
  algorithms?: ("RS256" | "RS384" | "RS512" | "ES256" | "ES384" | "ES512")[];
  keySet?: JWTVerifyGetKey;
  activeTenantIds?: Set<string>;
};

type OidcClaims = JWTPayload & {
  scope?: string;
  permissions?: unknown;
  tenant_id?: unknown;
};

const CLOCK_TOLERANCE_SECONDS = 60;
const DEFAULT_ALGORITHMS = ["RS256"] as const;

function bearerToken(req: Request): string | null {
  const value = req.header("authorization");
  if (!value) return null;
  const match = /^Bearer ([^\s]+)$/.exec(value);
  return match?.[1] ?? null;
}

function claimString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 && value.length <= 256 ? value : null;
}

function scopesFromClaims(claims: OidcClaims): string[] {
  const fromScope = typeof claims.scope === "string" ? claims.scope.split(/\s+/).filter(Boolean) : [];
  const fromPermissions = Array.isArray(claims.permissions) ? claims.permissions.filter((item): item is string => typeof item === "string") : [];
  return Array.from(new Set([...fromScope, ...fromPermissions]));
}

function tenantIdFromClaims(claims: OidcClaims, tenantClaim: string): string {
  const value = claims[tenantClaim] ?? claims.tenant_id;
  const tenantId = claimString(value);
  if (!tenantId || !/^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$/.test(tenantId)) {
    throw new Error("invalid tenant claim");
  }
  return tenantId;
}

function contextFromClaims(claims: OidcClaims, config: OidcConfig): TenantAuthContext {
  const subject = claimString(claims.sub);
  if (!subject) throw new Error("missing subject claim");
  const scopes = scopesFromClaims(claims);
  if (!scopes.includes(config.requiredScope)) throw new Error("missing required scope");
  if (typeof claims.iat !== "number" || typeof claims.exp !== "number") throw new Error("missing token timestamps");
  return {
    subject,
    tenantId: tenantIdFromClaims(claims, config.tenantClaim),
    scopes,
    issuedAt: claims.iat,
    expiresAt: claims.exp,
  };
}

function challenge(res: Response, value: string): void {
  res.setHeader("WWW-Authenticate", `Bearer realm=\"folklore-privacy-gateway\", ${value}`);
}

export function createOidcTenantAuth(config: OidcConfig) {
  const algorithms = config.algorithms ?? [...DEFAULT_ALGORITHMS];
  const keySet = config.keySet ?? createRemoteJWKSet(new URL(config.jwksUrl));

  return async (req: Request, res: Response, next: NextFunction) => {
    const token = bearerToken(req);
    if (!token) {
      challenge(res, "error=\"invalid_token\"");
      return res.status(401).json({ error: "Bearer authentication is required." });
    }

    try {
      const { payload } = await jwtVerify<OidcClaims>(token, keySet, {
        issuer: config.issuer,
        audience: config.audience,
        algorithms,
        clockTolerance: CLOCK_TOLERANCE_SECONDS,
      });
      const context = contextFromClaims(payload, config);
      if (config.activeTenantIds && !config.activeTenantIds.has(context.tenantId)) {
        return res.status(403).json({ error: "The tenant is not active for this service." });
      }
      req.tenantAuth = context;
      return next();
    } catch (error) {
      if (error instanceof Error && error.message === "missing required scope") {
        challenge(res, `error=\"insufficient_scope\", scope=\"${config.requiredScope}\"`);
        return res.status(403).json({ error: "The bearer token lacks the required scope." });
      }
      challenge(res, "error=\"invalid_token\"");
      return res.status(401).json({ error: "The bearer token is invalid, expired, or not intended for this service." });
    }
  };
}

export function createOidcTenantAuthFromEnv() {
  const issuer = process.env.FOLKLORE_OIDC_ISSUER;
  const audience = process.env.FOLKLORE_OIDC_AUDIENCE;
  const jwksUrl = process.env.FOLKLORE_OIDC_JWKS_URL;
  if (!issuer || !audience || !jwksUrl) {
    throw new Error("OIDC mode requires FOLKLORE_OIDC_ISSUER, FOLKLORE_OIDC_AUDIENCE, and FOLKLORE_OIDC_JWKS_URL");
  }
  return createOidcTenantAuth({
    issuer,
    audience,
    jwksUrl,
    tenantClaim: process.env.FOLKLORE_OIDC_TENANT_CLAIM ?? "https://folklore.example/tenant_id",
    requiredScope: process.env.FOLKLORE_OIDC_REQUIRED_SCOPE ?? "needs:submit",
    activeTenantIds: parseActiveTenantIds(),
  });
}
