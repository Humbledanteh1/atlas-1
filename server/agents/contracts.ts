import { createHash, createHmac } from "node:crypto";
import { redactSensitiveText } from "../privacy/redaction";
import { GuardDecision, inspectUntrustedText } from "../privacy/promptGuard";

export const AGENT_IDS = ["support", "inventory", "fulfillment", "marketing"] as const;
export type AgentId = (typeof AGENT_IDS)[number];

export type ClientNeedInput = {
  request: string;
  clientReference?: string;
  requestedAgent?: AgentId;
  tenantId?: string;
  referenceSecret?: string;
};

export type SharedNeedMessage = {
  messageType: "need-to-know";
  messageId: string;
  fromAgent: "privacy-gateway";
  toAgent: AgentId;
  purpose: string;
  needSummary: string;
  clientReference?: string;
  tenantId: string;
  allowedFields: string[];
  sensitivity: "redacted";
  expiresAt: string;
};

export type AgentRouting = {
  agent: AgentId;
  purpose: string;
  allowedFields: string[];
};

const ROUTES: Record<AgentId, AgentRouting> = {
  support: {
    agent: "support",
    purpose: "Prepare a human-reviewable customer-support next step.",
    allowedFields: ["issue_type", "order_status", "requested_resolution", "tone"],
  },
  inventory: {
    agent: "inventory",
    purpose: "Assess stock or supplier follow-up needs.",
    allowedFields: ["product_category", "stock_signal", "velocity_window", "supplier_action"],
  },
  fulfillment: {
    agent: "fulfillment",
    purpose: "Interpret delivery or order-exception needs.",
    allowedFields: ["order_status", "carrier_signal", "promised_date", "next_action"],
  },
  marketing: {
    agent: "marketing",
    purpose: "Prepare a privacy-safe campaign or feedback brief.",
    allowedFields: ["channel", "campaign_goal", "audience_segment", "performance_signal"],
  },
};

function opaqueClientReference(value: string, tenantId?: string, referenceSecret?: string): string {
  if (tenantId && referenceSecret) {
    const digest = createHmac("sha256", referenceSecret).update(`${tenantId}:${value}`).digest("hex").slice(0, 16);
    return `client-${digest}`;
  }
  const salt = process.env.CLIENT_REF_SALT ?? "folklore-local-development-only";
  const digest = createHash("sha256").update(`${salt}:${tenantId ?? "unscoped"}:${value}`).digest("hex").slice(0, 16);
  return `client-${digest}`;
}

export function chooseRoutes(input: ClientNeedInput): AgentRouting[] {
  if (input.requestedAgent && AGENT_IDS.includes(input.requestedAgent)) {
    return [ROUTES[input.requestedAgent]];
  }

  const request = input.request.toLowerCase();
  const selected = new Set<AgentId>();
  if (/(return|refund|ticket|customer|support|complaint)/.test(request)) selected.add("support");
  if (/(stock|inventory|reorder|supplier|sku|sold out)/.test(request)) selected.add("inventory");
  if (/(delivery|shipping|carrier|tracking|fulfillment|late order)/.test(request)) selected.add("fulfillment");
  if (/(campaign|marketing|ad|review|feedback|audience)/.test(request)) selected.add("marketing");

  if (selected.size === 0) selected.add("support");
  return Array.from(selected, (agent) => ROUTES[agent]);
}

export function buildSharedNeedMessages(input: ClientNeedInput, decision: GuardDecision): SharedNeedMessage[] {
  if (!decision.allowed) return [];

  const sanitized = redactSensitiveText(input.request).text.slice(0, 1200);
  const summary = `Client need (sanitized): ${sanitized}`;
  const clientReference = input.clientReference ? opaqueClientReference(input.clientReference, input.tenantId, input.referenceSecret) : undefined;
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

  return chooseRoutes(input).map((route, index) => ({
    messageType: "need-to-know" as const,
    messageId: `need-${Date.now()}-${index + 1}`,
    fromAgent: "privacy-gateway" as const,
    toAgent: route.agent,
    purpose: route.purpose,
    needSummary: summary,
    clientReference,
    tenantId: input.tenantId ?? "unscoped",
    allowedFields: route.allowedFields,
    sensitivity: "redacted" as const,
    expiresAt,
  }));
}

export function validateSharedNeedMessage(message: SharedNeedMessage): string[] {
  const errors: string[] = [];
  if (message.messageType !== "need-to-know") errors.push("invalid message type");
  if (!AGENT_IDS.includes(message.toAgent)) errors.push("unknown recipient agent");
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$/.test(message.tenantId)) errors.push("invalid tenant context");
  if (message.sensitivity !== "redacted") errors.push("message must be marked redacted");
  if (message.needSummary.length > 1400) errors.push("summary exceeds the outbound size limit");
  if (inspectUntrustedText(message.needSummary).risk === "high") errors.push("summary contains a blocked instruction");
  if (/\b(?:email|phone|password|secret|token|api[_ -]?key)\s*[:=]/i.test(message.needSummary)) {
    errors.push("summary appears to contain a direct sensitive field");
  }
  if (new Date(message.expiresAt).getTime() <= Date.now()) errors.push("message has expired");
  return errors;
}
