# TowerOps Agent

## Workflow

- Keep changes on a branch off the latest `main`; never commit or push directly to `main`.
- Run `make test`, `make vet`, and `make lint` before pushing.
- Use `make proto` after changing `proto/agent.proto`; keep it identical to the server's canonical schema.
- Use `gh pr create --base main` for pull requests.

## Conventions

- Preserve credential confidentiality in logs, errors, tests, and retained scheduler state.
- Bound queues by bytes where payload sizes vary, and make cancellation release workers, timers, sockets, and spool capacity.
- Keep the legacy wire path working when adding capability-gated protocol features.
- Prefer deterministic tests and existing package seams; avoid sleeps for synchronization.
