import type {
  ProofGraphNode,
  ProofRelationship,
} from "./proof-map-view-model";

export const FINDING_SUPPORT_FIELDS = new Set([
  "finding.fact_ids",
  "finding.evidence_ids",
  "fact.source_event_ids",
  "fact.source_observation_ids",
  "fact.source_fact_ids",
  "event.evidence_ids",
  "observation.evidence_ids",
]);

export type FindingInvestigation = {
  findingId: string;
  findingTitle: string;
  sessionId: string;
  captureId: string;
  nodeIds: Set<string>;
  edgeIds: Set<string>;
  nonCanvasPolicyRelationships: ProofRelationship[];
};

export type FindingInvestigationVisibility = {
  visibleNodeIds: Set<string>;
  visibleEdgeIds: Set<string>;
  hiddenNodeCount: number;
  hiddenEdgeCount: number;
};

export class ProofMapInvestigationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProofMapInvestigationError";
  }
}

const SUPPORT_ENDPOINT_KINDS: Record<
  string,
  { from: ProofGraphNode["kind"]; to: ProofGraphNode["kind"] }
> = {
  "finding.fact_ids": { from: "fact", to: "finding" },
  "finding.evidence_ids": { from: "evidence", to: "finding" },
  "fact.source_event_ids": { from: "event", to: "fact" },
  "fact.source_observation_ids": { from: "observation", to: "fact" },
  "fact.source_fact_ids": { from: "fact", to: "fact" },
  "event.evidence_ids": { from: "evidence", to: "event" },
  "observation.evidence_ids": { from: "evidence", to: "observation" },
};

function requireNode(
  nodesById: Map<string, ProofGraphNode>,
  id: string,
): ProofGraphNode {
  const node = nodesById.get(id);
  if (!node) {
    throw new ProofMapInvestigationError(
      `Finding support references an unresolved canvas node: ${id}`,
    );
  }
  return node;
}

function validateEligibleRelationships(
  nodesById: Map<string, ProofGraphNode>,
  relationships: ProofRelationship[],
): void {
  const relationshipIds = new Set<string>();
  const factSources = new Map<string, string[]>();

  for (const relationship of relationships) {
    if (!FINDING_SUPPORT_FIELDS.has(relationship.contractField)) continue;
    if (relationshipIds.has(relationship.relationshipId)) {
      throw new ProofMapInvestigationError(
        `Duplicate finding-support relationship: ${relationship.relationshipId}`,
      );
    }
    relationshipIds.add(relationship.relationshipId);

    const source = requireNode(nodesById, relationship.fromId);
    const target = requireNode(nodesById, relationship.toId);
    const expected = SUPPORT_ENDPOINT_KINDS[relationship.contractField];
    if (
      !expected ||
      source.kind !== expected.from ||
      target.kind !== expected.to ||
      relationship.fromKind !== expected.from ||
      relationship.toKind !== expected.to
    ) {
      throw new ProofMapInvestigationError(
        `${relationship.relationshipId} has endpoint kinds that do not match ${relationship.contractField}.`,
      );
    }
    if (
      source.captureId !== target.captureId ||
      !source.sessionIds.includes(relationship.sessionId) ||
      !target.sessionIds.includes(relationship.sessionId)
    ) {
      throw new ProofMapInvestigationError(
        `${relationship.relationshipId} crosses its declared session or capture boundary.`,
      );
    }
    if (relationship.contractField === "fact.source_fact_ids") {
      factSources.set(target.id, [
        ...(factSources.get(target.id) ?? []),
        source.id,
      ]);
    }
  }

  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visitFact = (factId: string): void => {
    if (visiting.has(factId)) {
      throw new ProofMapInvestigationError(
        `Finding-support fact cycle includes ${factId}.`,
      );
    }
    if (visited.has(factId)) return;
    visiting.add(factId);
    for (const sourceFactId of factSources.get(factId) ?? []) {
      visitFact(sourceFactId);
    }
    visiting.delete(factId);
    visited.add(factId);
  };
  for (const factId of factSources.keys()) visitFact(factId);
}

/**
 * Walk only upstream relationships explicitly eligible for finding support.
 * Graph integrity must already have been validated; the scope checks below are
 * defense in depth and must never convert an invalid relationship into a
 * partial successful investigation.
 */
export function buildFindingInvestigation(
  nodes: ProofGraphNode[],
  relationships: ProofRelationship[],
  findingId: string,
): FindingInvestigation {
  const nodesById = new Map(nodes.map((node) => [node.id, node]));
  const finding = requireNode(nodesById, findingId);
  if (finding.kind !== "finding" || finding.sessionIds.length !== 1) {
    throw new ProofMapInvestigationError(
      `${findingId} is not a session-scoped finding node.`,
    );
  }

  const sessionId = finding.sessionIds[0];
  const captureId = finding.captureId;
  validateEligibleRelationships(nodesById, relationships);
  const incoming = new Map<string, ProofRelationship[]>();
  for (const relationship of relationships) {
    if (!FINDING_SUPPORT_FIELDS.has(relationship.contractField)) continue;
    incoming.set(relationship.toId, [
      ...(incoming.get(relationship.toId) ?? []),
      relationship,
    ]);
  }

  const nodeIds = new Set([findingId]);
  const edgeIds = new Set<string>();
  const pending = [findingId];
  while (pending.length > 0) {
    const targetId = pending.pop()!;
    for (const relationship of incoming.get(targetId) ?? []) {
      if (relationship.sessionId !== sessionId) {
        throw new ProofMapInvestigationError(
          `${relationship.relationshipId} crosses the finding session boundary.`,
        );
      }
      const source = requireNode(nodesById, relationship.fromId);
      const target = requireNode(nodesById, relationship.toId);
      if (
        source.captureId !== captureId ||
        target.captureId !== captureId ||
        !source.sessionIds.includes(sessionId) ||
        !target.sessionIds.includes(sessionId)
      ) {
        throw new ProofMapInvestigationError(
          `${relationship.relationshipId} crosses the finding analysis scope.`,
        );
      }
      edgeIds.add(relationship.relationshipId);
      if (!nodeIds.has(source.id)) {
        nodeIds.add(source.id);
        // Evidence records are terminal even if shared with another dependent.
        if (source.kind !== "evidence") pending.push(source.id);
      }
    }
  }

  const evaluationIds = new Set(
    relationships
      .filter(
        (relationship) =>
          relationship.contractField === "evaluation.generated_finding_id" &&
          relationship.toId === findingId,
      )
      .map((relationship) => relationship.fromId),
  );
  const nonCanvasPolicyRelationships = relationships.filter(
    (relationship) =>
      relationship.relationshipType === "policy" &&
      (evaluationIds.has(relationship.fromId) ||
        evaluationIds.has(relationship.toId)) &&
      (!nodesById.has(relationship.fromId) || !nodesById.has(relationship.toId)),
  );

  return {
    findingId,
    findingTitle: finding.title,
    sessionId,
    captureId,
    nodeIds,
    edgeIds,
    nonCanvasPolicyRelationships,
  };
}

export function investigationVisibility(
  investigation: FindingInvestigation,
  visibleNodeIds: ReadonlySet<string>,
  visibleEdgeIds: ReadonlySet<string>,
): FindingInvestigationVisibility {
  const nodes = new Set(
    [...investigation.nodeIds].filter((id) => visibleNodeIds.has(id)),
  );
  const edges = new Set(
    [...investigation.edgeIds].filter((id) => visibleEdgeIds.has(id)),
  );
  return {
    visibleNodeIds: nodes,
    visibleEdgeIds: edges,
    hiddenNodeCount: investigation.nodeIds.size - nodes.size,
    hiddenEdgeCount: investigation.edgeIds.size - edges.size,
  };
}
