export type RedactionLabel =
  | "EMAIL"
  | "PHONE"
  | "PAYMENT_CARD"
  | "IP_ADDRESS"
  | "CREDENTIAL";

export type RedactionEvent = {
  label: RedactionLabel;
  count: number;
};

export type RedactionResult = {
  text: string;
  redactions: RedactionEvent[];
};

type Detector = {
  label: RedactionLabel;
  pattern: RegExp;
};

const ZERO_WIDTH = /[\u200B-\u200D\uFEFF]/g;

const DETECTORS: Detector[] = [
  {
    label: "EMAIL",
    pattern: /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi,
  },
  {
    label: "PAYMENT_CARD",
    pattern: /(?<!\d)(?:\d[ -]*?){13,19}(?!\d)/g,
  },
  {
    label: "IP_ADDRESS",
    pattern: /(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])/g,
  },
  {
    label: "PHONE",
    pattern: /(?<!\w)(?:\+?\d[\d\s().-]{7,}\d)(?!\w)/g,
  },
  {
    label: "CREDENTIAL",
    pattern:
      /\b(?:sk|pk|api|token|secret|password|passwd|authorization)[_-]?[A-Za-z0-9._-]{8,}\b/gi,
  },
];

function replacementFor(label: RedactionLabel): string {
  return `[REDACTED:${label}]`;
}

export function normalizeUntrustedText(value: string): string {
  return value.normalize("NFKC").replace(ZERO_WIDTH, "");
}

export function redactSensitiveText(value: string): RedactionResult {
  let text = normalizeUntrustedText(value);
  const counts = new Map<RedactionLabel, number>();

  for (const detector of DETECTORS) {
    detector.pattern.lastIndex = 0;
    text = text.replace(detector.pattern, () => {
      counts.set(detector.label, (counts.get(detector.label) ?? 0) + 1);
      return replacementFor(detector.label);
    });
  }

  return {
    text,
    redactions: Array.from(counts, ([label, count]) => ({ label, count })),
  };
}

export function redactSensitiveValue(value: unknown): {
  value: unknown;
  redactions: RedactionEvent[];
} {
  if (typeof value === "string") {
    const result = redactSensitiveText(value);
    return { value: result.text, redactions: result.redactions };
  }

  if (Array.isArray(value)) {
    const redactions: RedactionEvent[] = [];
    const next = value.map((item) => {
      const result = redactSensitiveValue(item);
      redactions.push(...result.redactions);
      return result.value;
    });
    return { value: next, redactions: mergeRedactionEvents(redactions) };
  }

  if (value && typeof value === "object") {
    const redactions: RedactionEvent[] = [];
    const next: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      const result = redactSensitiveValue(item);
      redactions.push(...result.redactions);
      next[key] = result.value;
    }
    return { value: next, redactions: mergeRedactionEvents(redactions) };
  }

  return { value, redactions: [] };
}

export function mergeRedactionEvents(events: RedactionEvent[]): RedactionEvent[] {
  const counts = new Map<RedactionLabel, number>();
  for (const event of events) {
    counts.set(event.label, (counts.get(event.label) ?? 0) + event.count);
  }
  return Array.from(counts, ([label, count]) => ({ label, count }));
}

export function hasSensitiveMarker(value: unknown): boolean {
  if (typeof value === "string") {
    return /\[REDACTED:[A-Z_]+\]/.test(value);
  }
  if (Array.isArray(value)) return value.some(hasSensitiveMarker);
  if (value && typeof value === "object") {
    return Object.values(value).some(hasSensitiveMarker);
  }
  return false;
}
