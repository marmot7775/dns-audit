# Correctness before refactoring

Date: 2026-09-14. Doc 49.

## Context

`audit_engine.py` is about 7,000 lines and `result_transformer.py` about
9,800, with more than twenty functions over 200 lines. Each is an obvious
refactoring target. Each also sits on a verdict path: the code that decides
what a domain owner is told about their mail. The review docs from 25 onward
found many cases where the tool stated something the audit had not
established. A refactor that moves that code without a test for each verdict
can bring those back silently.

## Decision

Wrong answers are fixed first and each fix gets a test that fails without
it. Structural work waits until the verdicts it touches are pinned, and then
runs as its own piece of work, never mixed into a correctness change. A
cleanup that would risk a verdict is skipped and reported, not done.

## Consequences

- The long modules stay long for now. The planned split is written down in
  [docs/proposals/checks-package.md](../proposals/checks-package.md) and runs
  in its own session.
- Dead code is removed only with tool output proving it dead, one module per
  commit, with the suite green.
