import { z } from "zod";

export const nodeTypeValues = [
  "function",
  "class",
  "module",
  "variable",
  "constant",
  "interface",
  "struct",
  "enum",
  "trait",
  "namespace",
  "package",
] as const;

export const relationshipTypeValues = [
  "calls",
  "inherits",
  "imports",
  "uses",
  "implements",
  "defined_in",
  "has_type",
  "depends_on",
  "similar_to",
] as const;

export const graphNodeSchema = z.object({
  id: z.string(),
  node_type: z.string(),
  name: z.string(),
  file_path: z.string(),
  line_number: z.number().int().nonnegative(),
  metadata: z.record(z.string()),
  properties: z.object({
    complexity: z.number(),
    importance: z.number(),
    in_degree: z.number().int().nonnegative(),
    out_degree: z.number().int().nonnegative(),
    tags: z.array(z.string()),
  }),
});

export const graphEdgeSchema = z.object({
  from: z.string(),
  to: z.string(),
  relationship: z.string(),
  weight: z.number(),
  context: z.string().nullable().optional(),
});

export const graphStatisticsSchema = z.object({
  total_nodes: z.number().int().nonnegative(),
  total_edges: z.number().int().nonnegative(),
  node_type_distribution: z.record(z.number().int().nonnegative()),
  relationship_type_distribution: z.record(z.number().int().nonnegative()),
});

export const semanticGraphSnapshotSchema = z.object({
  nodes: z.array(graphNodeSchema),
  edges: z.array(graphEdgeSchema),
  statistics: graphStatisticsSchema,
});

const analyzeReportWithGraphSchema = z
  .object({
    semantic_graph: semanticGraphSnapshotSchema,
  })
  .passthrough();

export const querySemanticGraphMetadataSchema = z.object({
  strategy: z.enum(["full_graph", "filter", "traversal", "relationship_filter"]),
  nodes_examined: z.number().int().nonnegative(),
  edges_examined: z.number().int().nonnegative(),
  max_results: z.number().int().positive(),
  traversal_depth: z.number().int().positive(),
  truncated: z.boolean(),
});

export const querySemanticGraphResultSchema = z.object({
  nodes: z.array(graphNodeSchema),
  edges: z.array(graphEdgeSchema),
  metadata: querySemanticGraphMetadataSchema,
});

export const querySemanticGraphReportSchema = z.object({
  source_command: z.literal("analyze"),
  graph_statistics: graphStatisticsSchema,
  query: z.object({
    path: z.string(),
    nodeType: z.enum(nodeTypeValues).optional(),
    namePattern: z.string().optional(),
    filePath: z.string().optional(),
    startNodeId: z.string().optional(),
    relationshipTypes: z.array(z.enum(relationshipTypeValues)).optional(),
    maxResults: z.number().int().positive(),
    traversalDepth: z.number().int().positive(),
  }),
  result: querySemanticGraphResultSchema,
});

export type GraphNode = z.infer<typeof graphNodeSchema>;
export type GraphEdge = z.infer<typeof graphEdgeSchema>;
export type SemanticGraphSnapshot = z.infer<typeof semanticGraphSnapshotSchema>;
export type QuerySemanticGraphReport = z.infer<typeof querySemanticGraphReportSchema>;

type QuerySemanticGraphInput = {
  path: string;
  nodeType?: typeof nodeTypeValues[number];
  namePattern?: string;
  filePath?: string;
  startNodeId?: string;
  relationshipTypes?: Array<typeof relationshipTypeValues[number]>;
  maxResults?: number;
  traversalDepth?: number;
};

function normalizeEnumName(value: string): string {
  return value
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[\s-]+/g, "_")
    .toLowerCase();
}

function relationshipMatches(edge: GraphEdge, relationshipTypes?: string[]): boolean {
  if (!relationshipTypes?.length) {
    return true;
  }

  return relationshipTypes.includes(normalizeEnumName(edge.relationship));
}

function nodeMatches(node: GraphNode, query: QuerySemanticGraphReport["query"]): boolean {
  if (query.nodeType && normalizeEnumName(node.node_type) !== query.nodeType) {
    return false;
  }

  if (query.namePattern && !node.name.includes(query.namePattern)) {
    return false;
  }

  if (query.filePath && !node.file_path.includes(query.filePath)) {
    return false;
  }

  return true;
}

function queryByTraversal(
  snapshot: SemanticGraphSnapshot,
  query: QuerySemanticGraphReport["query"]
): QuerySemanticGraphReport["result"] {
  if (!query.startNodeId) {
    throw new Error("Traversal queries require a startNodeId");
  }

  const nodeById = new Map(snapshot.nodes.map((node) => [node.id, node]));
  const edgesByFrom = new Map<string, GraphEdge[]>();

  for (const edge of snapshot.edges) {
    if (!relationshipMatches(edge, query.relationshipTypes)) {
      continue;
    }

    const existing = edgesByFrom.get(edge.from);
    if (existing) {
      existing.push(edge);
    } else {
      edgesByFrom.set(edge.from, [edge]);
    }
  }

  const resultNodes: GraphNode[] = [];
  const resultEdges: GraphEdge[] = [];
  const visited = new Set<string>();
  const seenEdges = new Set<string>();
  const queue: Array<{ nodeId: string; depth: number }> = [
    { nodeId: query.startNodeId, depth: 0 },
  ];
  let edgesExamined = 0;

  while (queue.length > 0 && resultNodes.length < query.maxResults) {
    const current = queue.shift();
    if (!current || visited.has(current.nodeId)) {
      continue;
    }

    visited.add(current.nodeId);
    const node = nodeById.get(current.nodeId);
    if (!node) {
      continue;
    }

    if (!nodeMatches(node, query)) {
      continue;
    }

    resultNodes.push(node);

    if (current.depth >= query.traversalDepth) {
      continue;
    }

    for (const edge of edgesByFrom.get(current.nodeId) ?? []) {
      edgesExamined += 1;
      const edgeKey = `${edge.from}:${edge.relationship}:${edge.to}:${edge.context ?? ""}`;
      if (!seenEdges.has(edgeKey)) {
        seenEdges.add(edgeKey);
        resultEdges.push(edge);
      }

      if (!visited.has(edge.to)) {
        queue.push({ nodeId: edge.to, depth: current.depth + 1 });
      }
    }
  }

  return {
    nodes: resultNodes,
    edges: resultEdges,
    metadata: {
      strategy: "traversal",
      nodes_examined: visited.size,
      edges_examined: edgesExamined,
      max_results: query.maxResults,
      traversal_depth: query.traversalDepth,
      truncated: queue.length > 0,
    },
  };
}

function queryByFilters(
  snapshot: SemanticGraphSnapshot,
  query: QuerySemanticGraphReport["query"]
): QuerySemanticGraphReport["result"] {
  const hasNodeFilters = Boolean(query.nodeType || query.namePattern || query.filePath);
  const filteredNodes = hasNodeFilters
    ? snapshot.nodes.filter((node) => nodeMatches(node, query))
    : snapshot.nodes;
  const selectedNodes = filteredNodes.slice(0, query.maxResults);
  const selectedIds = new Set(selectedNodes.map((node) => node.id));

  if (!hasNodeFilters && query.relationshipTypes?.length) {
    const selectedEdges = snapshot.edges
      .filter((edge) => relationshipMatches(edge, query.relationshipTypes))
      .slice(0, query.maxResults);
    const edgeNodeIds = new Set(selectedEdges.flatMap((edge) => [edge.from, edge.to]));
    const edgeNodes = snapshot.nodes.filter((node) => edgeNodeIds.has(node.id));

    return {
      nodes: edgeNodes,
      edges: selectedEdges,
      metadata: {
        strategy: "relationship_filter",
        nodes_examined: snapshot.nodes.length,
        edges_examined: snapshot.edges.length,
        max_results: query.maxResults,
        traversal_depth: query.traversalDepth,
        truncated:
          snapshot.edges.filter((edge) => relationshipMatches(edge, query.relationshipTypes)).length >
          selectedEdges.length,
      },
    };
  }

  const selectedEdges = snapshot.edges.filter((edge) => {
    if (!relationshipMatches(edge, query.relationshipTypes)) {
      return false;
    }

    return selectedIds.has(edge.from) && selectedIds.has(edge.to);
  });

  return {
    nodes: selectedNodes,
    edges: selectedEdges,
    metadata: {
      strategy: hasNodeFilters ? "filter" : "full_graph",
      nodes_examined: snapshot.nodes.length,
      edges_examined: snapshot.edges.length,
      max_results: query.maxResults,
      traversal_depth: query.traversalDepth,
      truncated: filteredNodes.length > selectedNodes.length,
    },
  };
}

export function buildSemanticGraphQueryReport(
  analyzeReport: unknown,
  input: QuerySemanticGraphInput
): QuerySemanticGraphReport {
  const parsedReport = analyzeReportWithGraphSchema.parse(analyzeReport);
  const query = {
    path: input.path,
    nodeType: input.nodeType,
    namePattern: input.namePattern,
    filePath: input.filePath,
    startNodeId: input.startNodeId,
    relationshipTypes: input.relationshipTypes,
    maxResults: input.maxResults ?? 100,
    traversalDepth: input.traversalDepth ?? 3,
  } satisfies QuerySemanticGraphReport["query"];

  const result = input.startNodeId
    ? queryByTraversal(parsedReport.semantic_graph, query)
    : queryByFilters(parsedReport.semantic_graph, query);

  return querySemanticGraphReportSchema.parse({
    source_command: "analyze",
    graph_statistics: parsedReport.semantic_graph.statistics,
    query,
    result,
  });
}
