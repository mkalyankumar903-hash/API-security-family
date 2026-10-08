import { createHash } from "node:crypto";
import YAML, { isAlias, visit } from "yaml";

export type SecurityRequirement = Record<string, string[]>;
export type Operation = { key: string; method: string; path: string; operationId: string | null; security: SecurityRequirement[] | null; pointer: string };
export type NormalizedSpec = { format: "OPENAPI_3_1" | "SWAGGER_2"; fingerprint: string; source: unknown; operations: Operation[]; schemes: string[]; servers: string[]; warnings: string[] };
export type Observation = { ruleId: string; ruleVersion: string; operationKey: string | null; category: string; explanation: string; evidencePointer: string; confidence: "SPEC_OBSERVATION"; validationLevel: "SPEC_ONLY"; reviewRequired: true; remediation: string };

const methods = ["get", "head", "post", "put", "patch", "delete", "options", "trace"];
const cap = 1024 * 1024;
export function parseSpec(sourceText: string): NormalizedSpec {
  if (typeof sourceText !== "string" || Buffer.byteLength(sourceText, "utf8") > cap || sourceText.length === 0) throw new Error("INVALID_SPEC_SIZE");
  let parsed: unknown;
  if (/^\s*[\[{]/.test(sourceText)) parsed = JSON.parse(sourceText);
  else {
    const doc = YAML.parseDocument(sourceText, { uniqueKeys: true, strict: true });
    if (doc.errors.length) throw new Error("INVALID_YAML: " + doc.errors[0]?.message);
    visit(doc, (_, node) => { if (isAlias(node)) throw new Error("YAML_ALIASES_PROHIBITED"); });
    parsed = doc.toJS({ maxAliasCount: 0 });
  }
  let nodes = 0;
  function check(o: unknown, depth = 0): void {
    if (++nodes > 30000 || depth > 45) throw new Error("SPEC_COMPLEXITY_LIMIT");
    if (o && typeof o === "object") {
      for (const [k, v] of Object.entries(o)) {
        if (k === "$ref" && typeof v === "string" && !v.startsWith("#/")) throw new Error("EXTERNAL_REF_PROHIBITED");
        check(v, depth + 1);
      }
    }
  }
  check(parsed);
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") throw new Error("INVALID_SPEC_ROOT");
  const root = parsed as Record<string, unknown>;
  const format = typeof root.openapi === "string" && /^3\.1\.\d+/.test(root.openapi) ? "OPENAPI_3_1" : root.swagger === "2.0" ? "SWAGGER_2" : null;
  if (!format) throw new Error("UNSUPPORTED_SPEC_VERSION");
  const paths = root.paths;
  if (!paths || typeof paths !== "object" || Array.isArray(paths)) throw new Error("MISSING_PATHS");
  const components = (root.components && typeof root.components === "object" ? root.components : {}) as Record<string, unknown>;
  const definitions = (format === "OPENAPI_3_1" ? components.securitySchemes : root.securityDefinitions) as Record<string, unknown> | undefined;
  const schemes = definitions && typeof definitions === "object" && !Array.isArray(definitions) ? Object.keys(definitions).sort() : [];
  function requirements(v: unknown): SecurityRequirement[] | null {
    if (v === undefined) return null;
    if (!Array.isArray(v)) throw new Error("INVALID_SECURITY_REQUIREMENTS");
    return v.map(item => {
      if (!item || Array.isArray(item) || typeof item !== "object") throw new Error("INVALID_SECURITY_REQUIREMENT");
      const output: SecurityRequirement = {};
      for (const [k, scopes] of Object.entries(item)) {
        if (!Array.isArray(scopes) || scopes.some(x => typeof x !== "string")) throw new Error("INVALID_SECURITY_SCOPES");
        output[k] = scopes as string[];
      }
      return output;
    });
  }
  const defaultSecurity = requirements(root.security);
  const operations: Operation[] = [];
  for (const [path, obj] of Object.entries(paths)) {
    if (!path.startsWith("/") || !obj || typeof obj !== "object" || Array.isArray(obj)) throw new Error("INVALID_PATH_ITEM");
    const item = obj as Record<string, unknown>;
    for (const method of methods) {
      if (item[method] === undefined) continue;
      const op = item[method];
      if (!op || typeof op !== "object" || Array.isArray(op)) throw new Error("INVALID_OPERATION");
      const data = op as Record<string, unknown>;
      const pointer = "/paths/" + path.replace(/~/g, "~0").replace(/\//g, "~1") + "/" + method;
      operations.push({ key: method.toUpperCase() + " " + path, method: method.toUpperCase(), path, operationId: typeof data.operationId === "string" ? data.operationId : null, security: data.security === undefined ? defaultSecurity : requirements(data.security), pointer });
      if (operations.length > 5000) throw new Error("TOO_MANY_OPERATIONS");
    }
  }
  const servers: string[] = [];
  if (format === "OPENAPI_3_1") {
    for (const entry of Array.isArray(root.servers) ? root.servers : []) {
      if (entry && typeof entry === "object" && typeof (entry as {url?:unknown}).url === "string") servers.push((entry as {url:string}).url);
    }
  } else if (typeof root.host === "string") servers.push((root.schemes as string[] | undefined)?.includes("http") ? "http://" + root.host : "https://" + root.host);
  return { format, fingerprint: createHash("sha256").update(sourceText).digest("hex"), source: parsed, operations: operations.sort((a,b) => a.key.localeCompare(b.key)), schemes, servers, warnings: ["Specification analysis does not prove runtime authorization, exploitability or API safety."] };
}
export function assess(spec: NormalizedSpec): Observation[] {
  const observations: Observation[] = [];
  function add(ruleId: string, operationKey: string | null, category: string, explanation: string, evidencePointer: string, remediation: string) {
    observations.push({ ruleId, ruleVersion: "1.0.0", operationKey, category, explanation, evidencePointer, confidence: "SPEC_OBSERVATION", validationLevel: "SPEC_ONLY", reviewRequired: true, remediation });
  }
  const secured = spec.operations.filter(op => op.security && op.security.length > 0).length;
  for (const op of spec.operations) {
    if (!op.security || op.security.length === 0) add("SPEC_AUTH_UNDECLARED", op.key, "AUTH_DECLARATION", "No effective OpenAPI security requirement is declared. Runtime authentication is unknown.", op.pointer + "/security", "Review server-side authentication and document intended security requirements.");
    if (/\/(users|accounts|admin|payments|billing|tokens|keys|secrets|orders)\b/i.test(op.path) && (!op.security || op.security.length === 0)) add("SPEC_SENSITIVE_UNDECLARED", op.key, "SENSITIVE_ROUTE", "Potentially sensitive path lacks a declared security requirement; this is not proof of an authorization vulnerability.", op.pointer, "Verify server-side authorization and document the security requirement.");
    for (const requirement of op.security ?? []) for (const scheme of Object.keys(requirement)) {
      if (!spec.schemes.includes(scheme)) add("SPEC_UNKNOWN_SCHEME", op.key, "SCHEME_REFERENCE", "Operation references an undefined security scheme: " + scheme, op.pointer + "/security", "Define or correct the referenced security scheme.");
    }
  }
  if (secured > 0 && secured < spec.operations.length) add("SPEC_INCONSISTENT_AUTH", null, "AUTH_CONSISTENCY", "Operations have mixed declared protection levels; review whether intentional.", "/paths", "Review and document per-operation security policy.");
  for (const [idx, url] of spec.servers.entries()) if (/^http:\/\//i.test(url)) add("SPEC_HTTP_SERVER", null, "TRANSPORT", "Specification declares an HTTP server; TLS configuration needs human review.", "/servers/" + idx, "Prefer HTTPS and verify TLS enforcement at runtime.");
  return observations.sort((a,b)=> (a.ruleId + (a.operationKey ?? "")).localeCompare(b.ruleId + (b.operationKey ?? "")));
}
