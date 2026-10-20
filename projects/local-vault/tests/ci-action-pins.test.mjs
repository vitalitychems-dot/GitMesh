import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

const WORKFLOWS = new URL("../../../.github/workflows/", import.meta.url);
const SHA = "a".repeat(40);

// This dependency-free policy intentionally supports block-style declarations.
// Reject aliases, complex keys and flow mappings instead of allowing YAML syntax
// to hide an action. Literal/folded script bodies are not action declarations.
function lexicalLine(line) {
  let plain = "";
  let quote = "";
  for (let index = 0; index < line.length; index++) {
    const char = line[index];
    if (quote) {
      plain += " ";
      if (quote === '"' && char === "\\") { plain += " "; index++; }
      else if (char === quote) {
        if (quote === "'" && line[index + 1] === "'") { plain += " "; index++; }
        else quote = "";
      }
    } else if (char === "#" && (index === 0 || /\s/.test(line[index - 1]))) {
      return { code: line.slice(0, index).trimEnd(), comment: line.slice(index + 1).trim(), plain };
    } else if (char === "'" || char === '"') {
      quote = char;
      plain += " ";
    } else {
      plain += char;
    }
  }
  if (quote) throw new Error("multiline quoted scalars are unsupported; use a block scalar");
  return { code: line.trimEnd(), comment: "", plain };
}

function referenceProblem(reference, comment) {
  if (reference.startsWith("./")) {
    const local = reference.slice(2);
    if (!/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/.test(local) ||
        local.split("/").some((part) => part === "." || part === "..")) {
      return "local references must stay inside the repository and have no ref suffix";
    }
    if (local.startsWith(".github/workflows") &&
        !/^\.github\/workflows\/[^/]+\.ya?ml$/.test(local)) {
      return "local reusable workflows must name a .yml or .yaml file directly in .github/workflows";
    }
    return null;
  }
  const external = /^([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)((?:\/[A-Za-z0-9_.-]+)*)@([a-fA-F0-9]{40})$/.exec(reference);
  if (!external || reference.split(/[/@]/).some((part) => part === "." || part === "..")) {
    return "external actions and reusable workflows require a full 40-hex commit SHA (Docker and expression refs are unsupported)";
  }
  if (external[2].startsWith("/.github/workflows") &&
      !/^\/\.github\/workflows\/[^/]+\.ya?ml$/.test(external[2])) {
    return "external reusable workflows must name a .yml or .yaml file directly in .github/workflows";
  }
  if (!/\bv\d+(?:\.\d+){0,2}(?:[-+][A-Za-z0-9.-]+)?\b/.test(comment)) {
    return "external pins require a readable release comment, for example # v4.4.0";
  }
  return null;
}

function workflowProblems(text, filename) {
  const problems = [];
  let scalarIndent = null;
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    if (!line.trim() || line.trimStart().startsWith("#")) continue;
    const indent = line.match(/^ */)[0].length;
    if (scalarIndent !== null) {
      if (indent > scalarIndent) continue;
      scalarIndent = null;
    }
    const report = (message) => problems.push(`${filename}:${index + 1}: ${message}`);
    try {
      if (/^ *\t/.test(line)) throw new Error("tab indentation is unsupported");
      const { code, comment, plain } = lexicalLine(line);
      const structural = plain.replace(/\$\{\{.*?\}\}/g, "");
      if (/[{}]/.test(structural) || /(^|\s)[&*!][A-Za-z]/.test(structural) ||
          /^\s*(?:-\s+)?(?:\?|<<:)/.test(structural)) {
        throw new Error("use block mappings without YAML aliases, tags or complex keys");
      }
      const entry = /^(\s*(?:-\s+)?)(uses|"uses"|'uses')\s*:\s*(.*?)\s*$/.exec(code);
      const quotedKey = /^\s*(?:-\s+)?(['"]).*?\1\s*:/.test(code);
      if (quotedKey && !entry) throw new Error("only a literal uses key may be quoted");
      if (/\buses\s*:/.test(structural) && !entry) {
        throw new Error("put each uses declaration on its own block-mapping line");
      }
      if (entry) {
        let reference = entry[3];
        if (reference.startsWith('"')) reference = JSON.parse(reference);
        else if (reference.startsWith("'")) {
          if (!/^'(?:[^']|'')*'$/.test(reference)) throw new Error("invalid quoted uses reference");
          reference = reference.slice(1, -1).replaceAll("''", "'");
        }
        const problem = referenceProblem(reference, comment);
        if (problem) report(problem);
      }
      if (/:\s*[|>](?:[1-9][+-]?|[+-][1-9]?)?\s*$/.test(code)) {
        scalarIndent = indent + (/^\s*-\s+/.exec(code)?.[0].trimStart().length || 0);
      }
    } catch (error) {
      report(error.message);
    }
  }
  return problems;
}

async function directoryProblems(directory) {
  const names = (await readdir(directory)).filter((name) => /\.ya?ml$/.test(name)).sort();
  const problems = [];
  for (const name of names) {
    const text = await readFile(new URL(encodeURIComponent(name), directory), "utf8");
    problems.push(...workflowProblems(text, name));
  }
  return { names, problems };
}

test("every repository workflow uses immutable external pins with release comments", async () => {
  const { names, problems } = await directoryProblems(WORKFLOWS);
  assert.ok(names.length > 0, "No workflow files were checked");
  assert.deepEqual(problems, []);
});

test("source-sync workflow uses reviewed immutable action pins with release comments", async () => {
  const workflow = await readFile(new URL("../../../.github/workflows/local-vault-regressions.yml", import.meta.url), "utf8");
  const actions = [...workflow.matchAll(/^\s*uses:\s*(\S+)\s*#\s*(v[\d.]+)\s*$/gm)];
  assert.equal(actions.length, 2);
  assert.deepEqual(actions.map((m) => [m[1], m[2]]), [
    ["actions/checkout@11d5960a326750d5838078e36cf38b85af677262", "v4.4.0"],
    ["actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020", "v4.4.0"],
  ]);
  assert.equal([...workflow.matchAll(/^\s*uses:/gm)].length, actions.length);
  assert.match(workflow, /contents: read/);
  assert.match(workflow, /persist-credentials: false/);
});

test("policy accepts pinned actions, local actions and explicitly supported reusable workflows", () => {
  const fixtures = [
    `- uses: actions/checkout@${SHA} # v4.4.0`,
    `- "uses": "owner/repo/sub-action@${SHA}" # sub-action v2.3.4`,
    `uses: 'owner/repo/.github/workflows/build.yaml@${SHA}' # v1.2.3`,
    "uses: ./.github/workflows/build.yml",
    "- uses: ./actions/local-build",
    "env:\n  VALUE: ${{ github.ref }}\nrun: |\n  uses: fake/action@main",
    "- run: >-\n    uses: fake/action@main\n  name: A script",
  ];
  for (const fixture of fixtures) assert.deepEqual(workflowProblems(fixture, "valid.yml"), [], fixture);
});

test("policy rejects mutable tags, missing release comments and malformed commit hashes", () => {
  const fixtures = [
    ["actions/checkout@v4 # v4.4.0", /40-hex/],
    ["actions/checkout@main # v4.4.0", /40-hex/],
    [`actions/checkout@${SHA}`, /release comment/],
    [`actions/checkout@${SHA} # reviewed`, /release comment/],
    [`actions/checkout@${"a".repeat(39)} # v4.4.0`, /40-hex/],
    [`actions/checkout@${"a".repeat(41)} # v4.4.0`, /40-hex/],
    [`actions/checkout@${"z".repeat(40)} # v4.4.0`, /40-hex/],
    [`owner/repo/.github/workflows/build.yml@main # v1.0.0`, /40-hex/],
    [`owner/repo/.github/workflows/build.yml@${SHA}`, /release comment/],
    [`owner/repo/.github/workflows/nested/build.yml@${SHA} # v1.0.0`, /directly in/],
    ["./../outside", /inside the repository/],
    ["./.github/workflows/build.yml@main", /no ref suffix/],
    ["./.github/workflows/build.json", /directly in/],
    [`docker://alpine@sha256:${"a".repeat(64)} # v3.0.0`, /Docker/],
  ];
  for (const [reference, reason] of fixtures) {
    const problems = workflowProblems(`  - uses: ${reference}`, "invalid.yml");
    assert.equal(problems.length, 1, reference);
    assert.match(problems[0], reason, reference);
  }
});

test("unsupported YAML forms cannot hide a mutable uses entry", () => {
  for (const fixture of [
    "steps: [{ uses: actions/checkout@main }]",
    "steps: [ uses: actions/checkout@main ]",
    '  "\\u0075ses": actions/checkout@main',
    "steps: *hidden",
    "? uses\n: actions/checkout@main",
    'name: "multiline\n  uses: actions/checkout@main"',
  ]) {
    assert.ok(workflowProblems(fixture, "unsupported.yaml").length > 0, fixture);
  }
});

test("new .yml and .yaml workflows are scanned, while non-workflow files are ignored", async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "gitmesh-ci-policy-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const directory = pathToFileURL(root + path.sep);
  await writeFile(new URL("existing.yml", directory), `uses: actions/checkout@${SHA} # v4.4.0\n`);
  await writeFile(new URL("new.yaml", directory), "uses: owner/repo@main # v1.0.0\n");
  await writeFile(new URL("notes.txt", directory), "uses: owner/repo@main\n");
  let result = await directoryProblems(directory);
  assert.deepEqual(result.names, ["existing.yml", "new.yaml"]);
  assert.equal(result.problems.length, 1);
  assert.match(result.problems[0], /^new\.yaml:1:.*40-hex/);
  await writeFile(new URL("another.yml", directory), `uses: owner/repo@${SHA}\n`);
  result = await directoryProblems(directory);
  assert.equal(result.problems.length, 2);
  assert.ok(result.problems.some((problem) => /^another\.yml:1:.*release comment/.test(problem)));
  await writeFile(path.join(root, "release #1.yaml"), "uses: owner/repo@main # v1.0.0\n");
  result = await directoryProblems(directory);
  assert.equal(result.problems.length, 3);
  assert.ok(result.problems.some((problem) => /^release #1\.yaml:1:.*40-hex/.test(problem)));
});
