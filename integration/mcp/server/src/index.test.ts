import { afterEach, describe, expect, it } from "vitest";
import { createServer } from "./index.js";
import { MCP_SCHEMA_VERSION, toolDefinitions } from "./tool-definitions.js";

type RegisteredTool = {
  callback?: (args: Record<string, unknown>, extra: unknown) => Promise<{
    content: Array<{ type: "text"; text: string }>;
    structuredContent?: Record<string, unknown>;
    isError?: boolean;
  }>;
  handler?: (args: Record<string, unknown>, extra: unknown) => Promise<{
    content: Array<{ type: "text"; text: string }>;
    structuredContent?: Record<string, unknown>;
    isError?: boolean;
  }>;
};

type InternalServer = {
  _registeredTools: Record<string, RegisteredTool>;
  close(): Promise<void>;
};

const toolInputs: Record<string, Record<string, unknown>> = {
  analyze_codebase: {
    path: "/tmp/project",
    depth: "deep",
    detailed: true,
    threads: 4,
  },
  get_symbols: {
    path: "/tmp/project",
  },
  query_code: {
    path: "/tmp/project",
    pattern: "(function_item name: (identifier) @name)",
    language: "rust",
    context: 2,
  },
  scan_security: {
    path: "/tmp/project",
    minSeverity: "high",
    maxFileKb: 512,
  },
  analyze_dependencies: {
    path: "/tmp/project",
    vulnerabilities: true,
    licenses: true,
  },
};

const serversToClose = new Set<InternalServer>();

afterEach(async () => {
  for (const server of serversToClose) {
    await server.close();
  }

  serversToClose.clear();
});

function getRegisteredTools(server: ReturnType<typeof createServer>): InternalServer {
  const internalServer = server as unknown as InternalServer;
  serversToClose.add(internalServer);
  return internalServer;
}

async function invokeTool(
  tool: RegisteredTool,
  input: Record<string, unknown>
): Promise<{
  content: Array<{ type: "text"; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}> {
  const handler = tool.handler ?? tool.callback;

  if (!handler) {
    throw new Error("Registered MCP tool handler is missing");
  }

  return handler(input, {});
}

describe("createServer", () => {
  it("registers handlers for every audited tool and returns the MCP envelope", async () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const server = getRegisteredTools(
      createServer(async (command, args) => {
        calls.push({ command, args });
        return {
          ok: true,
          command,
          args,
        };
      })
    );

    expect(Object.keys(server._registeredTools)).toEqual(
      toolDefinitions.map((tool) => tool.name)
    );

    for (const tool of toolDefinitions) {
      const input = toolInputs[tool.name];
      const result = await invokeTool(server._registeredTools[tool.name], input);

      expect(result.content).toEqual([
        {
          type: "text",
          text: `${tool.title} completed for /tmp/project`,
        },
      ]);
      expect(result.structuredContent).toEqual({
        schema_version: MCP_SCHEMA_VERSION,
        tool: tool.name,
        command: tool.command,
        path: "/tmp/project",
        report: {
          ok: true,
          command: tool.command,
          args: tool.buildArgs(input),
        },
      });
    }

    expect(calls).toEqual(
      toolDefinitions.map((tool) => ({
        command: tool.command,
        args: tool.buildArgs(toolInputs[tool.name]),
      }))
    );
  });

  it("returns MCP error results when the CLI runner fails", async () => {
    const server = getRegisteredTools(
      createServer(async () => {
        throw new Error("CLI unavailable");
      })
    );

    const result = await invokeTool(
      server._registeredTools.scan_security,
      toolInputs.scan_security
    );

    expect(result.isError).toBe(true);
    expect(result.content).toEqual([
      {
        type: "text",
        text: "Scan Security failed: CLI unavailable",
      },
    ]);
  });
});
