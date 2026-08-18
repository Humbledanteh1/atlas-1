# Atlas 1

Atlas 1 is a privacy-preserving client-data gateway for multi-agent workflows. It redacts common identifiers, detects prompt-injection and exfiltration attempts, creates bounded need-to-know messages, authenticates tenants with OIDC/JWT or an explicit HMAC development fallback, and provides PostgreSQL row-level-security guidance for defense in depth.

> **Core invariant:** raw client data is never forwarded to downstream agents.

## Quick start

Install dependencies, run the security suite, type-check the project, and build the API:

```bash
pnpm install --frozen-lockfile
pnpm test
pnpm check
pnpm build
```

Start the built server with:

```bash
NODE_ENV=production PORT=3000 node dist/index.js
```

The health endpoint is `GET /api/privacy/health`. The protected endpoint is `POST /api/privacy/needs`.

## OIDC configuration

The recommended mode is provider-neutral OIDC/JWT validation using a cached JWKS. Configure the service with deployment-managed environment variables:

```bash
FOLKLORE_AUTH_MODE=oidc
FOLKLORE_OIDC_ISSUER=https://idp.example.com/
FOLKLORE_OIDC_AUDIENCE=https://api.example.com
FOLKLORE_OIDC_JWKS_URL=https://idp.example.com/.well-known/jwks.json
FOLKLORE_OIDC_TENANT_CLAIM=https://atlas.example/tenant_id
FOLKLORE_OIDC_REQUIRED_SCOPE=needs:submit
FOLKLORE_REFERENCE_SECRET=another-secret-for-opaque-client-references
FOLKLORE_ACTIVE_TENANTS=tenant-alpha,tenant-beta
```

The verifier in `server/oidc.ts` validates the JWT signature, issuer, audience, allowed asymmetric algorithm, expiry and issuance time, required scope, tenant claim, and active-tenant allowlist. It reads permissions from both the standard `scope` claim and an optional `permissions` array. The tenant is never accepted from a request body or arbitrary header.

| Provider | Issuer | JWKS endpoint | Tenant claim configuration |
| --- | --- | --- | --- |
| Auth0 | `https://YOUR_DOMAIN/` | `https://YOUR_DOMAIN/.well-known/jwks.json` | Add a namespaced custom claim such as `https://atlas.example/tenant_id` with an Action; enable API RBAC if using `permissions` |
| Keycloak | `https://HOST/realms/REALM` | `https://HOST/realms/REALM/protocol/openid-connect/certs` | Add a tenant claim with a protocol mapper and request the required client scope |

Use an access token whose audience is the Atlas API, not an ID token. Auth0’s JWKS guidance is available in its [JSON Web Key Sets documentation](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets). Keycloak documents its OIDC discovery, certificate endpoint, local JWT validation, and introspection options in [Securing applications and services with OpenID Connect](https://www.keycloak.org/securing-apps/oidc-layers).

The compact `fpv1` HMAC verifier remains available only when `FOLKLORE_AUTH_MODE=hmac`. It is intended for local development and controlled service-to-service experiments, not as a replacement for an identity provider.

## API example

```bash
curl -sS -X POST http://localhost:3000/api/privacy/needs \
  -H 'Authorization: Bearer <short-lived-access-token>' \
  -H 'content-type: application/json' \
  --data '{
    "request": "A customer with jane.doe@example.com needs a refund because a delivery is late.",
    "clientReference": "CRM-4821"
  }'
```

A successful response contains redaction metadata, an opaque tenant-bound client reference, selected recipients, allowlisted fields, and `audit.rawClientDataForwarded: false`. An unauthenticated request receives `401`; insufficient scope or inactive tenants receive `403`; invalid or expired tokens receive `401`.

## Adversarial regression tests

Custom attack vectors belong in `server/adversarial-vectors.test.ts`. Use synthetic payloads only, and test the complete gateway pipeline:

```ts
const vector = {
  name: "custom attack name",
  input: "synthetic payload with no real client data",
};

const result = processClientNeed({ request: vector.input });
expect(result.status).toBe("blocked");
expect(result.outboundMessages).toHaveLength(0);
expect(result.audit.rawClientDataForwarded).toBe(false);
```

Add a paired benign example when a detector could create false positives. Existing coverage includes direct overrides, zero-width obfuscation, encoded instructions, persistent poisoning, markup exfiltration, unsafe tool requests, and forged privileged messages.

## PostgreSQL row-level security

The migration in [`db/postgres/001_tenant_rls.sql`](db/postgres/001_tenant_rls.sql) creates tenant-aware `client_records` and `agent_messages` tables, enables and forces RLS, and filters rows through the transaction-local setting `app.tenant_id`.

Set tenant context from the verified OIDC claim on the same pooled connection and inside the same transaction as the protected query:

```ts
const client = await pool.connect();
try {
  await client.query("BEGIN");
  await client.query("SELECT set_config('app.tenant_id', $1, true)", [req.tenantAuth!.tenantId]);
  const result = await client.query("SELECT * FROM app.client_records");
  await client.query("COMMIT");
  return result.rows;
} catch (error) {
  await client.query("ROLLBACK");
  throw error;
} finally {
  client.release();
}
```

The `true` parameter makes the setting transaction-local. Do not use separate pool queries for setting context and reading data, because they may run on different physical connections. The runtime role must be a least-privilege role that is not a superuser, table owner, or `BYPASSRLS` role. PostgreSQL’s official guidance is in [Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) and [CREATE POLICY](https://www.postgresql.org/docs/current/sql-createpolicy.html).

The migration is PostgreSQL-specific. If Atlas is connected to MySQL or another database, use the corresponding tenant-isolation mechanism or move protected records to PostgreSQL. RLS should be defense in depth; API authorization and database policy must both be enforced.

## Security model

Atlas minimizes and redacts data before inter-agent routing, rejects unsafe instruction content, binds opaque references to tenant context, and records metadata rather than raw client payloads. Production deployments should add HTTPS, key rotation, provider-side token revocation strategy, tenant lifecycle checks backed by a database, encrypted storage, retention and deletion controls, protected audit logs, distributed rate limiting, dependency scanning, and an independent security review.

## Repository layout

| Path | Purpose |
| --- | --- |
| `server/oidc.ts` | Provider-neutral OIDC/JWT verification with cached JWKS |
| `server/auth.ts` | HMAC fallback and tenant context types |
| `server/privacyRoutes.ts` | Authenticated API routes and tenant-aware rate limiting |
| `server/privacy/redaction.ts` | Deterministic PII and credential redaction |
| `server/privacy/promptGuard.ts` | Prompt-injection and exfiltration detection |
| `server/agents/contracts.ts` | Need-to-know agent contracts and routing |
| `server/agents/orchestrator.ts` | Privacy gateway decision flow |
| `db/postgres/001_tenant_rls.sql` | PostgreSQL tenant schema and RLS policies |
| `server/*.test.ts` | Authentication, adversarial, privacy, and OIDC regression tests |

## References

- [Auth0 JSON Web Key Sets](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets)
- [Keycloak OpenID Connect layers](https://www.keycloak.org/securing-apps/oidc-layers)
- [PostgreSQL Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [OWASP Multi-Tenant Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html)
