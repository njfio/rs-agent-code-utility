### CI workflow: opt JavaScript actions into Node.js 24

`ci.yml` now sets `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: "true"` at the workflow
level (matching `release.yml` from v0.6.1), opting `actions/checkout@v4` and
`actions/cache@v4` into the Node.js 24 runtime ahead of the 2026-06-02 forced
migration off Node 20. Silences the deprecation annotation on every CI run.
Reversible — drop once these actions ship Node-24 manifests by default.
