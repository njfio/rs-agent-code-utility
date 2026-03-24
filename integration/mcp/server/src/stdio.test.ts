import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { toolDefinitions } from "./tool-definitions.js";

const SOURCE_DIR = dirname(fileURLToPath(import.meta.url));
const SERVER_ROOT = resolve(SOURCE_DIR, "..");
const TSX_CLI_PATH = resolve(SERVER_ROOT, "node_modules/tsx/dist/cli.mjs");
const SERVER_ENTRY_PATH = resolve(SOURCE_DIR, "index.ts");

const clientsToClose = new Set<Client>();
const transportsToClose = new Set<StdioClientTransport>();

afterEach(async () => {
  for (const client of clientsToClose) {
    await client.close();
  }

  for (const transport of transportsToClose) {
    await transport.close();
  }

  clientsToClose.clear();
  transportsToClose.clear();
});

describe("stdio MCP server", () => {
  it("responds to tools/list with the shipped tool set", async () => {
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [TSX_CLI_PATH, SERVER_ENTRY_PATH],
      cwd: SERVER_ROOT,
      stderr: "pipe",
    });
    const client = new Client({
      name: "codex-mcp-test-client",
      version: "0.1.0",
    });

    transportsToClose.add(transport);
    clientsToClose.add(client);

    await client.connect(transport);

    const result = await client.listTools();

    expect(result.tools.map((tool) => tool.name)).toEqual(
      toolDefinitions.map((tool) => tool.name)
    );
  });
});
