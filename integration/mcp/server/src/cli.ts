import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const SOURCE_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPO_ROOT = resolve(SOURCE_DIR, "../../../../");
const DEFAULT_CLI_PATH = resolve(DEFAULT_REPO_ROOT, "target/debug/tree-sitter-cli");
const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_BUFFER_BYTES = 50 * 1024 * 1024;

export type CliJsonRunner = (
  subcommand: string,
  args: string[],
  options?: { timeoutMs?: number }
) => Promise<unknown>;

export type CliInvocation = {
  command: string;
  args: string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
  timeoutMs: number;
};

export class CliInvocationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CliInvocationError";
  }
}

export function buildCliInvocation(
  subcommand: string,
  args: string[],
  options?: { timeoutMs?: number }
): CliInvocation {
  const command = process.env.RTS_CLI_PATH ?? DEFAULT_CLI_PATH;
  const cwd = process.env.RTS_REPO_ROOT ?? DEFAULT_REPO_ROOT;

  return {
    command,
    args: [subcommand, "--no-color", ...args],
    cwd,
    env: {
      ...process.env,
      NO_COLOR: "1",
    },
    timeoutMs: options?.timeoutMs ?? DEFAULT_TIMEOUT_MS,
  };
}

export async function runCliJson(
  subcommand: string,
  args: string[],
  options?: { timeoutMs?: number }
): Promise<unknown> {
  const invocation = buildCliInvocation(subcommand, args, options);

  try {
    const { stdout } = await execFileAsync(invocation.command, invocation.args, {
      cwd: invocation.cwd,
      env: invocation.env,
      timeout: invocation.timeoutMs,
      maxBuffer: DEFAULT_MAX_BUFFER_BYTES,
    });

    if (!stdout.trim()) {
      throw new CliInvocationError(
        `CLI command '${subcommand}' returned empty JSON output`
      );
    }

    return JSON.parse(stdout);
  } catch (error) {
    if (error instanceof CliInvocationError) {
      throw error;
    }

    if (error instanceof SyntaxError) {
      throw new CliInvocationError(
        `CLI command '${subcommand}' returned invalid JSON: ${error.message}`
      );
    }

    if (typeof error === "object" && error !== null) {
      const stderr =
        "stderr" in error && typeof error.stderr === "string"
          ? error.stderr.trim()
          : "";
      const stdout =
        "stdout" in error && typeof error.stdout === "string"
          ? error.stdout.trim()
          : "";
      const message =
        stderr || stdout || (error instanceof Error ? error.message : String(error));
      throw new CliInvocationError(
        `CLI command '${subcommand}' failed: ${message}`
      );
    }

    throw new CliInvocationError(
      `CLI command '${subcommand}' failed: ${String(error)}`
    );
  }
}
