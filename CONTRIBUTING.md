# Contributing

## Licensing and the DCO

This project, including `proto/agent.proto` and its generated bindings in
`pb/`, is licensed **GPL-3.0-or-later**. See [LICENSE](LICENSE).

Contributions are accepted under GPL-3.0-or-later. We use the
[Developer Certificate of Origin](https://developercertificate.org/)
rather than a CLA: you keep your copyright, and you certify that you have the
right to contribute the work. Sign off every commit:

```bash
git commit -s
```

That appends a line naming you:

```
Signed-off-by: Your Name <you@example.com>
```

Use a real name and a working address; `-s` fills both from your git config.
Amend a commit you forgot to sign with `git commit -s --amend`.

Because this is a DCO rather than a CLA, you retain your copyright and the
project cannot be relicensed without the agreement of everyone who has
contributed. That is deliberate: it is the same guarantee the GPL gives our
users, applied to contributors.

By signing off you are certifying the DCO, reproduced here in full:

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

New files should carry the matching SPDX header:

```go
// Copyright (C) 2026 Your Name
// SPDX-License-Identifier: GPL-3.0-or-later
```

## Reporting security issues

Do not open a pull request or issue for a vulnerability. See
[SECURITY.md](SECURITY.md).

## Development

The repository ships a locked Nix dev shell using the Go 1.27 release line.
With [direnv](https://direnv.net/) the environment loads on `cd`; otherwise:

```bash
nix develop
```

The Go minimum is 1.27.2. `flake.lock` pins package inputs; narrow stable-release
overrides keep the linter, Git and gopls current while nixpkgs packaging catches
up. Refresh the lock and review those overrides together rather than assuming
an input update supplies the latest upstream tools. CI's explicit
golangci-lint version must match the supported compiler and shell.

| Tool | Selected stable release |
|------|-------------------------|
| Go | 1.27.2 |
| golangci-lint | 2.15.0 |
| protobuf compiler | 36.2 |
| protoc-gen-go / Go protobuf runtime | 1.36.12 |
| Git | 2.56.0 |
| gopls | 0.24.0 |
| Delve | 1.27.2 |

```bash
make test     # go test -race -count=1 ./...
make vet
make lint
make build
make proto    # regenerate pb/ after editing proto/agent.proto
```

`make proto` is the only supported protobuf-regeneration invocation, and its
output is committed. Never hand-edit `pb/agent.pb.go`: the `go_package` option
is embedded in the serialized descriptor as a length-prefixed string, so
editing the path by hand leaves a stale length and panics at init.

The canonical wire contract is `towerops-web/priv/proto/agent.proto`. Change
that schema and the server's hand-written codecs first, mirror everything
from `syntax = "proto3";` onward here, then regenerate with `make proto`.
The sibling server's `.forgejo/scripts/check-agent-proto-sync.sh` checks the
schema bodies. Cross-language fixtures in `testdata/` and the server's
`test/fixtures/proto/` check actual message semantics; their producer source
values are recorded in `proto_interop_test.go` and the server's
`test/towerops/proto/interop_test.exs`. Binding regeneration does not regenerate
those fixtures.

After upgrades, run the quality gates and exercise the binary against the
actual Phoenix agent endpoint with disposable credentials. Cover complete
and empty inventories, reconnect, probes and backups; a schema match or a
codec's own round trip is not interoperability proof. Release notifications
require both bearer authentication and a timestamped HMAC over the exact
body; do not disable the server verifier to accommodate CI.

Run `make vet lint test` before pushing; CI runs the same checks and a build.

## Pull requests

- One logical change per PR.
- Explain *why* in the commit message, not just what.
- Add tests for new behaviour; do not disable a failing test to make CI pass.
- CI must be green. Release images are scanned with Grype and the build fails
  on any finding of high severity or above.
