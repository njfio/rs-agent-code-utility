import { pathToFileURL } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { runCliJson, type CliJsonRunner } from "./cli.js";
import { MCP_SCHEMA_VERSION, toolDefinitions } from "./tool-definitions.js";

export function createServer(runCli: CliJsonRunner = runCliJson): McpServer {
  const server = new McpServer(
    {
      name: "codex-mcp-integration",
      version: "0.1.0",
    },
    {
      capabilities: {
        logging: {},
      },
    }
  );

  for (const tool of toolDefinitions) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.inputSchema.shape,
        outputSchema: tool.outputSchema.shape,
      },
      async (input: Record<string, unknown>): Promise<CallToolResult> => {
        const path =
          input && typeof input === "object" && "path" in input && typeof input.path === "string"
            ? input.path
            : "";

        try {
          const report = await tool.execute(runCli, input as Record<string, unknown>);
          const structuredContent = tool.outputSchema.parse({
            schema_version: MCP_SCHEMA_VERSION,
            tool: tool.name,
            command: tool.command,
            path,
            report,
          });

          const result: CallToolResult = {
            content: [
              {
                type: "text",
                text: `${tool.title} completed for ${path}`,
              },
            ],
            structuredContent: structuredContent as Record<string, unknown>,
          };

          return result;
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);

          const result: CallToolResult = {
            isError: true,
            content: [
              {
                type: "text",
                text: `${tool.title} failed: ${message}`,
              },
            ],
          };

          return result;
        }
      }
    );
  }

  return server;
}

export async function main(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}
