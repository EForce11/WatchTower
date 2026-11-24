# Detection rules

Sigma-compatible YAML rules (see docs/architecture.md section 4.2).

## Layout

    rules/
      wes-mapping.yaml            Sigma field name -> WES field path
      <scope>/<os>/<service>/     e.g. agent/linux/sshd/
        <name>.yml                one rule per file
        <name>.samples.yml        test events for that rule

## Conventions

- One rule per file. Multi-document files are tolerated by the loader but
  discouraged; they share a single samples file.
- Rule `id` is a unique UUID. `level` is one of informational, low, medium,
  high, critical.
- `custom.scope` is `agent` or `core` (default `agent`).
- Every field in `detection` must be listed in `wes-mapping.yaml`.
- A correlation rule has `correlation:` instead of `detection:`, and its
  `correlation.rules` must reference existing rule ids.

## Samples file

    match:    [ <event>, ... ]   # must trigger the rule
    no_match: [ <event>, ... ]   # false-positive regression corpus

Events are WES field maps. Both keys are required; either list may be empty.
Phase 0 checks presence and parseability only; the matching engine arrives in
Phase 2.

## Checking

    go test ./internal/rules/
