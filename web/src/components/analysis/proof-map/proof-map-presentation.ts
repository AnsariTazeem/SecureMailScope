import type { ChainOfProof } from "@/lib/contracts/chain";

// Fixed card geometry is shared by DOM sizing, React Flow and lane layout.
// Compact column gaps limit the zoom penalty of wider, wrapped cards.
export const proofGeometry = {
  width: 260,
  height: 132,
  columnGap: 48,
  rowGap: 28,
} as const;

export function readableToken(value: string): string {
  return value.replaceAll("_", " ").replace(/\btls\b/gi, "TLS")
    .replace(/\bstarttls\b/gi, "STARTTLS").replace(/\btcp\b/gi, "TCP");
}

export function suppliedValue(value: unknown): string {
  if (value === true) return "Yes (true)";
  if (value === false) return "No (false)";
  if (value === null) return "Null — no supplied value";
  if (value === undefined) return "Value unavailable";
  if (value === "") return "Empty string";
  return typeof value === "string" ? value : JSON.stringify(value);
}

export function factTitle(type: string): string {
  const titles: Record<string, string> = {
    tls_upgrade_completed: "TLS upgrade completion",
    starttls_advertised: "STARTTLS advertisement",
    plaintext_commands_after_offer: "Plaintext commands after offer",
    negotiated_tls_version: "Negotiated TLS version",
    certificate_observability: "Certificate visibility",
    forward_secrecy: "Forward Secrecy assessment",
  };
  return titles[type] ?? `Fact: ${readableToken(type)}`;
}

export function eventState(event: ChainOfProof["protocol_events"][number]) {
  if (event.event_status === "incomplete_capture") return "incomplete_capture";
  if (event.event_status === "not_observable") return "not_observable";
  if (event.event_status === "inferred" && event.observability === "observed") return "derived";
  return event.observability;
}
