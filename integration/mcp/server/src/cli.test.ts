import { afterEach, describe, expect, it } from "vitest";
import { buildCliInvocation } from "./cli.js";

describe("buildCliInvocation", () => {
  afterEach(() => {
    delete process.env.RTS_CLI_PATH;
    delete process.env.RTS_REPO_ROOT;
  });

  it("builds a default invocation with no-color safeguards", () => {
    const invocation = buildCliInvocation("analyze", ["./src", "--format", "json"]);

    expect(invocation.command.endsWith("target/debug/tree-sitter-cli")).toBe(true);
    expect(invocation.args).toEqual([
      "analyze",
      "--no-color",
      "./src",
      "--format",
      "json",
    ]);
    expect(invocation.env.NO_COLOR).toBe("1");
    expect(invocation.timeoutMs).toBe(120_000);
  });

  it("honors environment overrides", () => {
    process.env.RTS_CLI_PATH = "/tmp/custom-cli";
    process.env.RTS_REPO_ROOT = "/tmp/custom-repo";

    const invocation = buildCliInvocation("symbols", ["./src", "--format", "json"], {
      timeoutMs: 5_000,
    });

    expect(invocation.command).toBe("/tmp/custom-cli");
    expect(invocation.cwd).toBe("/tmp/custom-repo");
    expect(invocation.timeoutMs).toBe(5_000);
  });
});
