import { z } from "zod";

export const MCP_SCHEMA_VERSION = "1" as const;

const pathSchema = z.string().min(1).describe("Path to a repository or source tree.");
const jsonReportSchema = z.any().describe("Raw JSON emitted by tree-sitter-cli.");

const baseOutputSchema = (tool: string, command: string) =>
  z.object({
    schema_version: z.literal(MCP_SCHEMA_VERSION),
    tool: z.literal(tool),
    command: z.literal(command),
    path: z.string(),
    report: jsonReportSchema,
  });

export const analyzeCodebaseInputSchema = z.object({
  path: pathSchema,
  maxSizeKb: z.number().int().positive().max(10240).optional(),
  maxDepth: z.number().int().positive().max(100).optional(),
  depth: z.enum(["basic", "deep", "full"]).optional(),
  includeHidden: z.boolean().optional(),
  excludeDirs: z.array(z.string().min(1)).optional(),
  includeExts: z.array(z.string().min(1)).optional(),
  detailed: z.boolean().optional(),
  threads: z.number().int().positive().max(128).optional(),
  enableSecurity: z.boolean().optional(),
});

export const getSymbolsInputSchema = z.object({
  path: pathSchema,
});

export const queryCodeInputSchema = z.object({
  path: pathSchema,
  pattern: z.string().min(1),
  language: z.string().min(1),
  prefilter: z.string().min(1).optional(),
  context: z.number().int().min(0).max(20).optional(),
});

export const scanSecurityInputSchema = z.object({
  path: pathSchema,
  minSeverity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
  depth: z.enum(["basic", "deep", "full"]).optional(),
  includeTests: z.boolean().optional(),
  includeExamples: z.boolean().optional(),
  includeNonCode: z.boolean().optional(),
  minConfidence: z.enum(["low", "medium", "high"]).optional(),
  enableSecurity: z.boolean().optional(),
  noAiFilter: z.boolean().optional(),
  filterMode: z.enum(["strict", "balanced", "permissive"]).optional(),
  maxFileKb: z.number().int().positive().max(10240).optional(),
});

export const analyzeDependenciesInputSchema = z.object({
  path: pathSchema,
  includeDev: z.boolean().optional(),
  vulnerabilities: z.boolean().optional(),
  licenses: z.boolean().optional(),
  outdated: z.boolean().optional(),
  graph: z.boolean().optional(),
});

export const analyzeCodebaseOutputSchema = baseOutputSchema(
  "analyze_codebase",
  "analyze"
);
export const getSymbolsOutputSchema = baseOutputSchema("get_symbols", "symbols");
export const queryCodeOutputSchema = baseOutputSchema("query_code", "query");
export const scanSecurityOutputSchema = baseOutputSchema("scan_security", "security");
export const analyzeDependenciesOutputSchema = baseOutputSchema(
  "analyze_dependencies",
  "dependencies"
);

export type ToolDefinition = {
  name: string;
  title: string;
  description: string;
  command: string;
  inputSchema: z.AnyZodObject;
  outputSchema: z.AnyZodObject;
  buildArgs: (input: Record<string, unknown>) => string[];
};

export function buildAnalyzeCodebaseArgs(input: z.infer<typeof analyzeCodebaseInputSchema>): string[] {
  const args = [input.path, "--format", "json"];

  if (input.maxSizeKb !== undefined) args.push("--max-size", String(input.maxSizeKb));
  if (input.maxDepth !== undefined) args.push("--max-depth", String(input.maxDepth));
  if (input.depth) args.push("--depth", input.depth);
  if (input.includeHidden) args.push("--include-hidden");
  if (input.excludeDirs?.length) args.push("--exclude-dirs", input.excludeDirs.join(","));
  if (input.includeExts?.length) args.push("--include-exts", input.includeExts.join(","));
  if (input.detailed) args.push("--detailed");
  if (input.threads !== undefined) args.push("--threads", String(input.threads));
  if (input.enableSecurity) args.push("--enable-security");

  return args;
}

export function buildGetSymbolsArgs(input: z.infer<typeof getSymbolsInputSchema>): string[] {
  return [input.path, "--format", "json"];
}

export function buildQueryCodeArgs(input: z.infer<typeof queryCodeInputSchema>): string[] {
  const args = [
    input.path,
    "--pattern",
    input.pattern,
    "--language",
    input.language,
    "--format",
    "json",
  ];

  if (input.prefilter) args.push("--prefilter", input.prefilter);
  if (input.context !== undefined) args.push("--context", String(input.context));

  return args;
}

export function buildScanSecurityArgs(input: z.infer<typeof scanSecurityInputSchema>): string[] {
  const args = [input.path, "--format", "json"];

  if (input.minSeverity) args.push("--min-severity", input.minSeverity);
  if (input.depth) args.push("--depth", input.depth);
  if (input.includeTests) args.push("--include-tests");
  if (input.includeExamples) args.push("--include-examples");
  if (input.includeNonCode) args.push("--include-non-code");
  if (input.minConfidence) args.push("--min-confidence", input.minConfidence);
  if (input.enableSecurity) args.push("--enable-security");
  if (input.noAiFilter) args.push("--no-ai-filter");
  if (input.filterMode) args.push("--filter-mode", input.filterMode);
  if (input.maxFileKb !== undefined) args.push("--max-file-kb", String(input.maxFileKb));

  return args;
}

export function buildAnalyzeDependenciesArgs(
  input: z.infer<typeof analyzeDependenciesInputSchema>
): string[] {
  const args = [input.path, "--format", "json"];

  if (input.includeDev) args.push("--include-dev");
  if (input.vulnerabilities) args.push("--vulnerabilities");
  if (input.licenses) args.push("--licenses");
  if (input.outdated) args.push("--outdated");
  if (input.graph) args.push("--graph");

  return args;
}

export const toolDefinitions: ToolDefinition[] = [
  {
    name: "analyze_codebase",
    title: "Analyze Codebase",
    description:
      "Run the analyze command and return the structured JSON report for a repository.",
    command: "analyze",
    inputSchema: analyzeCodebaseInputSchema,
    outputSchema: analyzeCodebaseOutputSchema,
    buildArgs: (input) =>
      buildAnalyzeCodebaseArgs(analyzeCodebaseInputSchema.parse(input)),
  },
  {
    name: "get_symbols",
    title: "Get Symbols",
    description:
      "Extract symbols grouped by file using the CLI's JSON symbol output.",
    command: "symbols",
    inputSchema: getSymbolsInputSchema,
    outputSchema: getSymbolsOutputSchema,
    buildArgs: (input) => buildGetSymbolsArgs(getSymbolsInputSchema.parse(input)),
  },
  {
    name: "query_code",
    title: "Query Code",
    description:
      "Run a tree-sitter query over a codebase and return the JSON match list.",
    command: "query",
    inputSchema: queryCodeInputSchema,
    outputSchema: queryCodeOutputSchema,
    buildArgs: (input) => buildQueryCodeArgs(queryCodeInputSchema.parse(input)),
  },
  {
    name: "scan_security",
    title: "Scan Security",
    description:
      "Run the main security pipeline and return the JSON security report.",
    command: "security",
    inputSchema: scanSecurityInputSchema,
    outputSchema: scanSecurityOutputSchema,
    buildArgs: (input) => buildScanSecurityArgs(scanSecurityInputSchema.parse(input)),
  },
  {
    name: "analyze_dependencies",
    title: "Analyze Dependencies",
    description:
      "Analyze dependency manifests and return the dependency report as JSON.",
    command: "dependencies",
    inputSchema: analyzeDependenciesInputSchema,
    outputSchema: analyzeDependenciesOutputSchema,
    buildArgs: (input) =>
      buildAnalyzeDependenciesArgs(analyzeDependenciesInputSchema.parse(input)),
  },
];
