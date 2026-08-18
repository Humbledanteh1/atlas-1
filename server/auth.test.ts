import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { processClientNeed } from "./agents/orchestrator";
import { parseActiveTenantIds, requireTenantAuth, verifyTenantToken } from "./auth";

const SECRET = "unit-test-secret-with-enough-entropy";

function makeToken(overrides: Partial<{ sub: string; tenantId: string; scopes: string[]; iat: number; exp: number; aud: string }> = {}, secret = SECRET) {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    sub: "operator-1",
    tenantId: "tenant-alpha",
    scopes: ["needs:submit"],
    iat: now,
    exp: now + 900,
    aud: "folklore-privacy-gateway",
    ...overrides,
  };
  const payload = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
  const signingInput = `fpv1.${payload}`;
  const signature = createHmac("sha256", secret).update(signingInput).digest("base64url");
  return `${signingInput}.${signature}`;
}

function fakeResponse() {
  const headers: Record<string, string> = {};
  const response = {
    statusCode: 200,
    body: null as unknown,
    setHeader(name: string, value: string) {
      headers[name] = value;
      return response;
    },
    status(code: number) {
      response.statusCode = code;
      return response;
    },
    json(body: unknown) {
      response.body = body;
      return response;
    },
    headers,
  };
  return response;
}

describe("tenant-aware authentication", () => {
  it("accepts a valid scoped token and returns its tenant context", () => {
    const context = verifyTenantToken(makeToken(), SECRET);
    expect(context).toMatchObject({ subject: "operator-1", tenantId: "tenant-alpha", scopes: ["needs:submit"] });
  });

  it("rejects a token signed by another service", () => {
    expect(() => verifyTenantToken(makeToken({}, "wrong-secret"), SECRET)).toThrow();
  });

  it("rejects expired tokens and tokens without the required scope", () => {
    expect(() => verifyTenantToken(makeToken({ exp: Math.floor(Date.now() / 1000) - 120 }), SECRET)).toThrow("token expired");
    expect(() => verifyTenantToken(makeToken({ scopes: ["needs:read"] }), SECRET)).toThrow("missing required scope");
  });

  it("rejects missing credentials and missing scopes at the middleware boundary", () => {
    const middleware = requireTenantAuth(SECRET);
    const missingRequest = { header: () => undefined } as any;
    const missingResponse = fakeResponse();
    let called = false;
    middleware(missingRequest, missingResponse as any, () => { called = true; });
    expect(missingResponse.statusCode).toBe(401);
    expect(missingResponse.headers["WWW-Authenticate"]).toContain("Bearer");
    expect(called).toBe(false);

    const scopeRequest = { header: (name: string) => name === "authorization" ? `Bearer ${makeToken({ scopes: ["needs:read"] })}` : undefined } as any;
    const scopeResponse = fakeResponse();
    middleware(scopeRequest, scopeResponse as any, () => { called = true; });
    expect(scopeResponse.statusCode).toBe(403);
    expect(scopeResponse.headers["WWW-Authenticate"]).toContain("insufficient_scope");
  });

  it("rejects a valid token for an inactive tenant", () => {
    const middleware = requireTenantAuth(SECRET, "needs:submit", parseActiveTenantIds("tenant-alpha"));
    const request = { header: (name: string) => name === "authorization" ? `Bearer ${makeToken({ tenantId: "tenant-beta" })}` : undefined } as any;
    const response = fakeResponse();
    middleware(request, response as any, () => { throw new Error("inactive tenant should not reach the handler"); });
    expect(response.statusCode).toBe(403);
    expect(response.body).toEqual({ error: "The tenant is not active for this service." });
  });

  it("keeps identical client references isolated across tenants", () => {
    const alpha = processClientNeed({ request: "The customer needs a refund.", clientReference: "CRM-42", tenantId: "tenant-alpha", referenceSecret: SECRET });
    const beta = processClientNeed({ request: "The customer needs a refund.", clientReference: "CRM-42", tenantId: "tenant-beta", referenceSecret: SECRET });
    expect(alpha.outboundMessages[0].tenantId).toBe("tenant-alpha");
    expect(beta.outboundMessages[0].tenantId).toBe("tenant-beta");
    expect(alpha.outboundMessages[0].clientReference).not.toBe(beta.outboundMessages[0].clientReference);
  });
});
