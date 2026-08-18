import { randomUUID } from "node:crypto";
import { buildSharedNeedMessages, ClientNeedInput, SharedNeedMessage, validateSharedNeedMessage } from "./contracts";
import { redactSensitiveText } from "../privacy/redaction";
import { GuardDecision, inspectUntrustedText, safeRefusal } from "../privacy/promptGuard";

export type PrivacyGatewayResult = {
  requestId: string;
  status: "forwarded" | "blocked" | "review";
  decision: GuardDecision;
  redactions: ReturnType<typeof redactSensitiveText>["redactions"];
  outboundMessages: SharedNeedMessage[];
  response: string;
  audit: {
    rawClientDataForwarded: false;
    recipients: string[];
    blockedReasons: string[];
  };
};

export function processClientNeed(input: ClientNeedInput): PrivacyGatewayResult {
  const requestId = randomUUID();
  const redacted = redactSensitiveText(input.request);
  const decision = inspectUntrustedText(input.request);

  if (!input.request.trim()) {
    return {
      requestId,
      status: "review",
      decision: { allowed: false, risk: "medium", score: 1, reasons: ["empty request"] },
      redactions: [],
      outboundMessages: [],
      response: "Please describe the client need before routing it.",
      audit: { rawClientDataForwarded: false, recipients: [], blockedReasons: ["empty request"] },
    };
  }

  if (!decision.allowed) {
    return {
      requestId,
      status: "blocked",
      decision,
      redactions: redacted.redactions,
      outboundMessages: [],
      response: safeRefusal(decision),
      audit: { rawClientDataForwarded: false, recipients: [], blockedReasons: decision.reasons },
    };
  }

  const candidateMessages = buildSharedNeedMessages(input, decision);
  const outboundMessages = candidateMessages.filter((message) => validateSharedNeedMessage(message).length === 0);
  const droppedMessages = candidateMessages.length - outboundMessages.length;
  const status = decision.risk === "medium" || droppedMessages > 0 ? "review" : "forwarded";
  const recipients = outboundMessages.map((message) => message.toAgent);

  return {
    requestId,
    status,
    decision,
    redactions: redacted.redactions,
    outboundMessages,
    response:
      status === "review"
        ? "The need was sanitized and queued for review. Only a redacted summary can be shared with another agent."
        : `The need was sanitized and shared with ${recipients.length} agent${recipients.length === 1 ? "" : "s"} on a need-to-know basis.`,
    audit: {
      rawClientDataForwarded: false,
      recipients,
      blockedReasons: droppedMessages > 0 ? ["one or more outbound messages failed validation"] : [],
    },
  };
}
