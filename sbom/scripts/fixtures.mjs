// Single fixture registry shared by truth generation, oracle runs and measurement.
// id: corpus/out/<id>/, artifact: file inside it, source: corpus/src/<source>/.
// rea: CLI command and target selection; "each-dll" runs once per published assembly.
export const FIXTURES = [
  {
    id: "go-uuid",
    ecosystem: "golang",
    source: "go-uuid",
    artifact: "go-uuid",
    rea: "inspect-go-binary",
  },
  {
    id: "go-uuid-stripped",
    ecosystem: "golang",
    source: "go-uuid",
    artifact: "go-uuid",
    rea: "inspect-go-binary",
  },
  {
    id: "go-jwt",
    ecosystem: "golang",
    source: "go-jwt",
    artifact: "go-jwt",
    rea: "inspect-go-binary",
  },
  {
    id: "go-jwt-stripped",
    ecosystem: "golang",
    source: "go-jwt",
    artifact: "go-jwt",
    rea: "inspect-go-binary",
  },
  {
    id: "rust-small",
    ecosystem: "cargo",
    source: "rust-small",
    artifact: "rust-small",
    rea: "inspect-rust-binary",
  },
  {
    id: "rust-vuln",
    ecosystem: "cargo",
    source: "rust-vuln",
    artifact: "rust-vuln",
    rea: "inspect-rust-binary",
  },
  {
    id: "dotnet-json",
    ecosystem: "nuget",
    source: "dotnet-json",
    artifact: "each-dll",
    rea: "inspect-managed-artifact",
  },
  {
    id: "dotnet-serilog",
    ecosystem: "nuget",
    source: "dotnet-serilog",
    artifact: "each-dll",
    rea: "inspect-managed-artifact",
  },
  {
    id: "npm-electron",
    ecosystem: "npm",
    source: "npm-electron",
    artifact: "app.asar",
    rea: "analyze-javascript-application",
  },
  {
    id: "npm-cli",
    ecosystem: "npm",
    source: "npm-cli",
    artifact: "app.asar",
    rea: "analyze-javascript-application",
  },
  {
    id: "py-requests",
    ecosystem: "pypi",
    source: "py-requests",
    artifact: "py-requests",
    rea: "inspect-artifact",
  },
  {
    id: "py-yaml",
    ecosystem: "pypi",
    source: "py-yaml",
    artifact: "py-yaml",
    rea: "inspect-artifact",
  },
  {
    id: "py-requests-meta",
    ecosystem: "pypi",
    source: "py-requests-meta",
    artifact: "py-requests-meta",
    rea: "inspect-artifact",
  },
];

// Not part of the baseline, the default build or the tests: held-out check of the PyInstaller
// bytecode spike on packages the module table was not written for (build_corpus.sh python_wide).
export const EXPERIMENT_FIXTURES = [
  {
    id: "py-wide",
    ecosystem: "pypi",
    source: "py-wide",
    artifact: "py-wide",
  },
];
