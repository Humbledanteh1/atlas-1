import { normalizeUntrustedText } from "./redaction";

export type GuardDecision = {
  allowed: boolean;
  risk: "low" | "medium" | "high";
  score: number;
  reasons: string[];
};

const INJECTION_RULES: Array<{ pattern: RegExp; reason: string; weight: number }> = [
  {
    pattern: /ignore\s+(all\s+)?(?:previous| prior| earlier)\s+instructions?/i,
    reason: "instruction override attempt",
    weight: 5,
  },
  {
    pattern: /(?:reveal|show|print|repeat|leak)\s+(?:the\s+)?(?:system|developer|hidden)\s+(?:prompt|instructions?)/i,
    reason: "hidden-instruction extraction attempt",
    weight: 5,
  },
  {
    pattern: /(?:api[_ -]?key|password|secret|token|credential).{0,32}(?:send|post|email|upload|share|publish|exfiltrat)/i,
    reason: "credential exfiltration attempt",
    weight: 6,
  },
  {
    pattern: /(?:send|post|upload|share|publish|forward).{0,48}(?:client|customer|private|personal|conversation|record|data)/i,
    reason: "private-data transfer attempt",
    weight: 5,
  },
  {
    pattern: /(?:you\s+are\s+now|act\s+as|switch\s+to|enter)\s+(?:developer|admin|root|unrestricted|jailbreak|DAN)/i,
    reason: "privilege or role escalation attempt",
    weight: 4,
  },
  {
    pattern: /(?:bypass|disable|turn\s+off|circumvent).{0,32}(?:security|filter|guardrail|privacy|policy|approval)/i,
    reason: "guardrail bypass attempt",
    weight: 5,
  },
  {
    pattern: /(?:do\s+not|don't)\s+(?:tell|show|log|mention|record).{0,48}(?:user|operator|audit|security)/i,
    reason: "audit-obfuscation attempt",
    weight: 4,
  },
  {
    pattern: /(?:remember|from\s+now\s+on|for\s+future\s+requests).{0,64}(?:ignore|override|reveal|send|share)/i,
    reason: "persistent instruction poisoning attempt",
    weight: 4,
  },
  {
    pattern: /<(?:img|iframe|script|a)\b[^>]*(?:src|href)\s*=\s*["']?https?:\/\/[^>]*(?:data|token|secret|client|private)/i,
    reason: "markup-based exfiltration attempt",
    weight: 5,
  },
  {
    pattern: /(?:call|invoke|execute|use)\s+(?:the\s+)?(?:tool|function|webhook).{0,64}(?:send|upload|delete|export|share)/i,
    reason: "unsafe tool-use attempt",
    weight: 5,
  },
  {
    pattern: /(?:system|developer|admin)\s*(?:instruction|message|override)\s*[:=]/i,
    reason: "forged privileged message",
    weight: 5,
  },
];

const SUSPICIOUS_TERMS = /\b(?:exfiltrate|jailbreak|prompt\s+injection|system\s+prompt|root\s+access|drop\s+table)\b/i;

function decodeBase64Candidate(value: string): string | null {
  const compact = value.replace(/\s+/g, "");
  if (compact.length < 24 || compact.length % 4 !== 0 || !/^[A-Za-z0-9+/=]+$/.test(compact)) {
    return null;
  }
  try {
    const decoded = Buffer.from(compact, "base64").toString("utf8");
    return /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(decoded) ? null : decoded;
  } catch {
    return null;
  }
}

export function inspectUntrustedText(value: string): GuardDecision {
  const normalized = normalizeUntrustedText(value).replace(/\s+/g, " ").trim();
  let score = 0;
  const reasons: string[] = [];

  for (const rule of INJECTION_RULES) {
    if (rule.pattern.test(normalized)) {
      score += rule.weight;
      reasons.push(rule.reason);
    }
  }

  if (SUSPICIOUS_TERMS.test(normalized)) {
    score += 1;
    reasons.push("security-sensitive language requires a boundary check");
  }

  const decoded = decodeBase64Candidate(normalized);
  if (decoded) {
    const decodedDecision = inspectUntrustedText(decoded);
    if (decodedDecision.score > 0) {
      score += decodedDecision.score;
      reasons.push("encoded instruction content detected");
    }
  }

  const uniqueReasons = Array.from(new Set(reasons));
  const risk = score >= 5 ? "high" : score > 0 ? "medium" : "low";
  return {
    allowed: score < 5,
    risk,
    score,
    reasons: uniqueReasons,
  };
}

export function safeRefusal(decision: GuardDecision): string {
  if (decision.allowed) return "";
  return "I can’t process that request because it conflicts with the privacy and security boundary. No client data was shared.";
}
