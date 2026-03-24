import { describe, expect, it } from "vitest";
import { buildSemanticGraphQueryReport } from "./semantic-graph.js";

const analyzeReport = {
  semantic_graph: {
    nodes: [
      {
        id: "node-alpha",
        node_type: "Function",
        name: "alpha",
        file_path: "/tmp/project/src/lib.rs",
        line_number: 10,
        metadata: {},
        properties: {
          complexity: 1,
          importance: 1,
          in_degree: 0,
          out_degree: 1,
          tags: [],
        },
      },
      {
        id: "node-beta",
        node_type: "Function",
        name: "beta",
        file_path: "/tmp/project/src/lib.rs",
        line_number: 20,
        metadata: {},
        properties: {
          complexity: 1,
          importance: 1,
          in_degree: 1,
          out_degree: 1,
          tags: [],
        },
      },
      {
        id: "node-gamma",
        node_type: "Class",
        name: "Gamma",
        file_path: "/tmp/project/src/model.rs",
        line_number: 5,
        metadata: {},
        properties: {
          complexity: 1,
          importance: 1,
          in_degree: 1,
          out_degree: 0,
          tags: [],
        },
      },
    ],
    edges: [
      {
        from: "node-alpha",
        to: "node-beta",
        relationship: "Calls",
        weight: 1,
        context: "alpha()",
      },
      {
        from: "node-beta",
        to: "node-gamma",
        relationship: "DependsOn",
        weight: 0.3,
        context: "same_file",
      },
    ],
    statistics: {
      total_nodes: 3,
      total_edges: 2,
      node_type_distribution: {
        Function: 2,
        Class: 1,
      },
      relationship_type_distribution: {
        Calls: 1,
        DependsOn: 1,
      },
    },
  },
};

describe("buildSemanticGraphQueryReport", () => {
  it("filters graph nodes by type", () => {
    const report = buildSemanticGraphQueryReport(analyzeReport, {
      path: "/tmp/project",
      nodeType: "function",
      maxResults: 10,
    });

    expect(report.result.nodes.map((node) => node.id)).toEqual([
      "node-alpha",
      "node-beta",
    ]);
    expect(report.result.metadata.strategy).toBe("filter");
  });

  it("traverses relationships from a starting node", () => {
    const report = buildSemanticGraphQueryReport(analyzeReport, {
      path: "/tmp/project",
      startNodeId: "node-alpha",
      relationshipTypes: ["calls"],
      traversalDepth: 2,
      maxResults: 10,
    });

    expect(report.result.nodes.map((node) => node.id)).toEqual([
      "node-alpha",
      "node-beta",
    ]);
    expect(report.result.edges).toEqual([
      {
        from: "node-alpha",
        to: "node-beta",
        relationship: "Calls",
        weight: 1,
        context: "alpha()",
      },
    ]);
    expect(report.result.metadata.strategy).toBe("traversal");
  });
});
