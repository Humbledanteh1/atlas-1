import { createHmac, timingSafeEqual } from "node:crypto";
import type { NextFunction, Request, Response } from "express";

export type TenantAuthContext = {
  subject: string;
  tenantId: string;
  scopes: string[];
  issuedAt: number;
  expiresAt: number;
};

type CompactTokenClaims = {
  sub: string;
  tenantId: string;
  scopes: string[];
  iat: number;
  exp: number;
  aud: string;
};

const TOKEN_PREFIX = "fpv1";
const EXPECTED_AUDIENCE = "folklore-privacy-gateway";
const CLOCK_SKEW_SECONDS = 60;
const MAX_TOKEN_LIFETIME_SECONDS = 24 * 60 * 60;

function decodeBase64Url(value: string): string {
  return Buffer.from(value, "base64url").toString("utf8");
}

function encodeBase64Url(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

function readClaims(payload: string): CompactTokenClaims {
  const parsed = JSON.parse(decodeBase64Url(payload)) as Partial<CompactTokenClaims>;
  if (
    typeof parsed.sub !== "string" ||
    parsed.sub.length < 1 ||
    parsed.sub.length > 200 ||
    typeof parsed.tenantId !== "string" ||
    !/^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$/.test(parsed.tenantId) ||
    !Array.isArray(parsed.scopes) ||
    parsed.scopes.some((scope) => typeof scope !== "string" || scope.length > 100) ||
    typeof parsed.iat !== "number" ||
    typeof parsed.exp !== "number" ||
    typeof parsed.aud !== "string"
  ) {
    throw new Error("invalid token claims");
  }
  return parsed as CompactTokenClaims;
}

export function verifyTenantToken(token: string, secret: string, requiredScope = "needs:submit"): TenantAuthContext {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== TOKEN_PREFIX || !secret) {
    throw new Error("invalid token format");
  }

  const signingInput = `${parts[0]}.${parts[1]}`;
  const expectedSignature = createHmac("sha256", secret).update(signingInput).digest();
  const receivedSignature = Buffer.from(parts[2], "base64url");
  if (receivedSignature.length !== expectedSignature.length || !timingSafeEqual(receivedSignature, expectedSignature)) {
    throw new Error("invalid token signature");
  }

  const claims = readClaims(parts[1]);
  const now = Math.floor(Date.now() / 1000);
  if (claims.aud !== EXPECTED_AUDIENCE) throw new Error("invalid token audience");
  if (claims.iat > now + CLOCK_SKEW_SECONDS) throw new Error("token issued in the future");
  if (claims.exp <= now - CLOCK_SKEW_SECONDS) throw new Error("token expired");
  if (claims.exp <= claims.iat || claims.exp - claims.iat > MAX_TOKEN_LIFETIME_SECONDS) throw new Error("invalid token lifetime");
  if (!claims.scopes.includes(requiredScope)) throw new Error("missing required scope");

  return {
    subject: claims.sub,
    tenantId: claims.tenantId,
    scopes: claims.scopes,
    issuedAt: claims.iat,
    expiresAt: claims.exp,
  };
}

function bearerToken(req: Request): string | null {
  const value = req.header("authorization");
  if (!value) return null;
  const match = /^Bearer ([^\s]+)$/.exec(value);
  return match?.[1] ?? null;
}

export function parseActiveTenantIds(value = process.env.FOLKLORE_ACTIVE_TENANTS): Set<string> | undefined {
  const ids = value?.split(",").map((item) => item.trim()).filter(Boolean) ?? [];
  return ids.length > 0 ? new Set(ids) : undefined;
}

export function requireTenantAuth(secret: string | undefined, requiredScope = "needs:submit", activeTenantIds?: Set<string>) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!secret) {
      return res.status(503).json({ error: "Authentication is not configured for this service." });
    }

    const token = bearerToken(req);
    if (!token) {
      res.setHeader("WWW-Authenticate", 'Bearer realm="folklore-privacy-gateway"');
      return res.status(401).json({ error: "Bearer authentication is required." });
    }

    try {
      const context = verifyTenantToken(token, secret, requiredScope);
      if (activeTenantIds && !activeTenantIds.has(context.tenantId)) {
        return res.status(403).json({ error: "The tenant is not active for this service." });
      }
      req.tenantAuth = context;
      return next();
    } catch (error) {
      if (error instanceof Error && error.message === "missing required scope") {
        res.setHeader("WWW-Authenticate", `Bearer realm="folklore-privacy-gateway", error="insufficient_scope", scope="${requiredScope}"`);
        return res.status(403).json({ error: "The bearer token lacks the required scope." });
      }
      res.setHeader("WWW-Authenticate", 'Bearer realm="folklore-privacy-gateway", error="invalid_token"');
      return res.status(401).json({ error: "The bearer token is invalid or expired." });
    }
  };
}

declare global {
  namespace Express {
    interface Request {
      tenantAuth?: TenantAuthContext;
    }
  }
}

export function tenantScopedReference(tenantId: string, clientReference: string, secret: string): string {
  const digest = createHmac("sha256", secret).update(`${tenantId}:${clientReference}`).digest("hex").slice(0, 16);
  return `client-${digest}`;
}

export function encodeClaimsForTest(claims: CompactTokenClaims): string {
  const payload = encodeBase64Url(JSON.stringify(claims));
  const signingInput = `${TOKEN_PREFIX}.${payload}`;
  const signature = createHmac("sha256", "test-only-secret").update(signingInput).digest("base64url");
  return `${signingInput}.${signature}`;
}
