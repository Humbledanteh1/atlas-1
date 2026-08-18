import { beforeAll, describe, expect, it } from "vitest";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { createOidcTenantAuth } from "./oidc";

const ISSUER = "https://idp.example.test/";
const AUDIENCE = "https://api.example.test";
const TENANT_CLAIM = "https://folklore.example/tenant_id";
const REQUIRED_SCOPE = "needs:submit";

let privateKey: Parameters<SignJWT["sign"]>[0];
let keySet: ReturnType<typeof createLocalJWKSet>;

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

async function makeToken(overrides: Record<string, unknown> = {}) {
  return new SignJWT({
    scope: REQUIRED_SCOPE,
    [TENANT_CLAIM]: "tenant-alpha",
    ...overrides,
  })
    .setProtectedHeader({ alg: "RS256", kid: "oidc-test-key" })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject("user-123")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
}

async function runMiddleware(token: string, activeTenantIds?: Set<string>) {
  const middleware = createOidcTenantAuth({
    issuer: ISSUER,
    audience: AUDIENCE,
    jwksUrl: "https://unused.test/jwks.json",
    tenantClaim: TENANT_CLAIM,
    requiredScope: REQUIRED_SCOPE,
    keySet,
    activeTenantIds,
  });
  const request = { header: (name: string) => name === "authorization" ? `Bearer ${token}` : undefined } as any;
  const response = fakeResponse();
  let called = false;
  await middleware(request, response as any, () => { called = true; });
  return { request, response, called };
}

beforeAll(async () => {
  const pair = await generateKeyPair("RS256");
  privateKey = pair.privateKey;
  const publicJwk = await exportJWK(pair.publicKey) as JWK;
  publicJwk.kid = "oidc-test-key";
  publicJwk.alg = "RS256";
  publicJwk.use = "sig";
  keySet = createLocalJWKSet({ keys: [publicJwk] });
});

describe("OIDC tenant authentication", () => {
  it("accepts a valid issuer, audience, scope, and tenant claim", async () => {
    const result = await runMiddleware(await makeToken());
    expect(result.called).toBe(true);
    expect(result.request.tenantAuth).toMatchObject({ subject: "user-123", tenantId: "tenant-alpha", scopes: [REQUIRED_SCOPE] });
  });

  it("rejects a token with the wrong issuer", async () => {
    const token = await new SignJWT({ scope: REQUIRED_SCOPE, [TENANT_CLAIM]: "tenant-alpha" })
      .setProtectedHeader({ alg: "RS256", kid: "oidc-test-key" })
      .setIssuer("https://attacker.example/")
      .setAudience(AUDIENCE)
      .setSubject("user-123")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);
    const result = await runMiddleware(token);
    expect(result.response.statusCode).toBe(401);
    expect(result.response.headers["WWW-Authenticate"]).toContain("invalid_token");
  });

  it("returns 403 when the token lacks the required scope", async () => {
    const result = await runMiddleware(await makeToken({ scope: "needs:read" }));
    expect(result.response.statusCode).toBe(403);
    expect(result.response.headers["WWW-Authenticate"]).toContain("insufficient_scope");
  });

  it("rejects a valid token for an inactive tenant", async () => {
    const result = await runMiddleware(await makeToken(), new Set(["tenant-beta"]));
    expect(result.response.statusCode).toBe(403);
    expect(result.response.body).toEqual({ error: "The tenant is not active for this service." });
  });
});
