import type { Express, NextFunction, Request, Response } from "express";
import { AGENT_IDS, type AgentId } from "./agents/contracts";
import { parseActiveTenantIds, requireTenantAuth } from "./auth";
import { createOidcTenantAuthFromEnv } from "./oidc";
import { processClientNeed } from "./agents/orchestrator";

const RATE_WINDOW_MS = 60_000;
const RATE_LIMIT = 30;
const requestWindows = new Map<string, { startedAt: number; count: number }>();

function rateLimit(req: Request, res: Response, next: NextFunction) {
  const now = Date.now();
  const key = req.tenantAuth ? `tenant:${req.tenantAuth.tenantId}` : req.ip ?? "anonymous";
  const current = requestWindows.get(key);
  if (!current || now - current.startedAt > RATE_WINDOW_MS) {
    requestWindows.set(key, { startedAt: now, count: 1 });
    return next();
  }
  current.count += 1;
  if (current.count > RATE_LIMIT) {
    return res.status(429).json({ error: "Too many requests. Try again shortly." });
  }
  return next();
}

function isAgentId(value: unknown): value is AgentId {
  return typeof value === "string" && AGENT_IDS.includes(value as AgentId);
}

function tenantAuthMiddleware() {
  return process.env.FOLKLORE_AUTH_MODE === "oidc"
    ? createOidcTenantAuthFromEnv()
    : requireTenantAuth(process.env.FOLKLORE_AUTH_SECRET, "needs:submit", parseActiveTenantIds());
}

function referenceSecret(): string | undefined {
  const value = process.env.FOLKLORE_REFERENCE_SECRET ?? (process.env.FOLKLORE_AUTH_MODE === "oidc" ? undefined : process.env.FOLKLORE_AUTH_SECRET);
  if (!value && process.env.NODE_ENV === "production") {
    throw new Error("Production privacy routing requires FOLKLORE_REFERENCE_SECRET");
  }
  return value;
}

export function registerPrivacyRoutes(app: Express): void {
  const tenantAuth = tenantAuthMiddleware();
  const clientReferenceSecret = referenceSecret();

  app.get("/api/privacy/health", (_req, res) => {
    res.json({
      ok: true,
      service: "folklore-privacy-gateway",
      authMode: process.env.FOLKLORE_AUTH_MODE === "oidc" ? "oidc" : "hmac-fallback",
      policy: "raw client data is never forwarded to downstream agents",
      agents: AGENT_IDS,
    });
  });

  app.post("/api/privacy/needs", tenantAuth, rateLimit, (req, res) => {
    const body = req.body as Record<string, unknown>;
    const tenant = req.tenantAuth;
    if (!tenant) return res.status(401).json({ error: "Authenticated tenant context is required." });
    if (!body || typeof body.request !== "string" || body.request.length > 8_000) {
      return res.status(400).json({ error: "request must be a non-empty string under 8,000 characters" });
    }
    if (body.requestedAgent !== undefined && !isAgentId(body.requestedAgent)) {
      return res.status(400).json({ error: "requestedAgent must name a supported agent" });
    }
    if (body.clientReference !== undefined && (typeof body.clientReference !== "string" || body.clientReference.length > 256)) {
      return res.status(400).json({ error: "clientReference must be a short string" });
    }

    const result = processClientNeed({
      request: body.request,
      clientReference: typeof body.clientReference === "string" ? body.clientReference : undefined,
      requestedAgent: isAgentId(body.requestedAgent) ? body.requestedAgent : undefined,
      tenantId: tenant.tenantId,
      referenceSecret: clientReferenceSecret,
    });

    console.info(JSON.stringify({
      event: "privacy_gateway_decision",
      requestId: result.requestId,
      status: result.status,
      risk: result.decision.risk,
      redactionTypes: result.redactions.map((item) => item.label),
      recipients: result.audit.recipients,
      tenantId: tenant.tenantId,
      subject: tenant.subject,
      rawClientDataForwarded: false,
    }));

    return res.status(200).json(result);
  });
}
