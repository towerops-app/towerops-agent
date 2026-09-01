# Contributing

## Licensing and the DCO

This project is licensed **GPL-3.0-or-later**, with one exception:
`proto/agent.proto` and the generated bindings in `pb/` are **Apache-2.0**, so
that implementing the wire protocol does not drag anything into copyleft. See
[LICENSE](LICENSE) and [LICENSE.Apache-2.0](LICENSE.Apache-2.0).

Contributions are accepted under the license of the file you are changing. We
use the [Developer Certificate of Origin](https://developercertificate.org/)
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

The repository ships a Nix dev shell with Go 1.27 selected explicitly and the
linter and protobuf compiler supplied by nixpkgs-unstable. With
[direnv](https://direnv.net/) the environment loads on
`cd`; otherwise:

```bash
nix develop
```

Using the shell matters more than it looks: only the Go version is selected
explicitly via `pkgs.go_1_27`. `golangci-lint` and `protoc-gen-go` follow the
flake's unpinned nixpkgs-unstable input, so CI's explicit linter version must be
kept in sync by hand. A mismatched `golangci-lint` will refuse to lint a module
targeting a newer Go than it was built with.

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

Run `make vet lint test` before pushing; CI runs the same checks and a build.

## Pull requests

- One logical change per PR.
- Explain *why* in the commit message, not just what.
- Add tests for new behaviour; do not disable a failing test to make CI pass.
- CI must be green. Release images are scanned with Grype and the build fails
  on any finding of high severity or above.
