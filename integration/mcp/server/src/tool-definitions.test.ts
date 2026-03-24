import { describe, expect, it } from "vitest";
import {
  MCP_SCHEMA_VERSION,
  buildAnalyzeCodebaseArgs,
  buildQuerySemanticGraphArgs,
  toolDefinitions,
} from "./tool-definitions.js";

describe("toolDefinitions", () => {
  it("registers the audited MCP tool set", () => {
    expect(toolDefinitions.map((tool) => tool.name)).toEqual([
      "analyze_codebase",
      "get_symbols",
      "query_code",
      "scan_security",
      "analyze_dependencies",
      "query_semantic_graph",
    ]);
  });

  it("every tool output schema includes schema_version", () => {
    for (const tool of toolDefinitions) {
      const result = tool.outputSchema.parse({
        schema_version: MCP_SCHEMA_VERSION,
        tool: tool.name,
        command: tool.command,
        path: "/tmp/project",
        report: {},
      });

      expect(result.schema_version).toBe(MCP_SCHEMA_VERSION);
    }
  });

  it("maps includeGraph to the analyze CLI flag", () => {
    expect(
      buildAnalyzeCodebaseArgs({
        path: "/tmp/project",
        includeGraph: true,
      })
    ).toContain("--include-graph");
  });

  it("builds semantic graph queries on top of analyze --include-graph", () => {
    expect(
      buildQuerySemanticGraphArgs({
        path: "/tmp/project",
        relationshipTypes: ["calls"],
      })
    ).toContain("--include-graph");
  });
});
