# AGENTS.md

sensible is a Go tool that configures Linux hosts. A controller reads YAML
config, plans each host's resources, and sends them to an agent on the host
over SSH (the same binary, run as `sensible agent`). See the README for usage.

## Layout

- `cmd/sensible`: CLI wiring only.
- `internal/config`: reads the config directory, including roles, partials,
  stacks and secrets, and merges it per host.
- `internal/features`: turns a host's config and facts into resources.
- `internal/host`: the agent, including resource implementations and the
  controller-agent protocol.
- `internal/run`: the controller, including bootstrap, planning, transports and
  agent builds.
- `test/containers`: disposable Debian and Arch hosts to try changes against.

## Checks

```sh
go test ./...
go vet ./...
make            # Builds ./sensible with embedded agents
```

Tests don't need the agents to be generated, but a binary used against real
hosts does. A plain `go build` skips `go generate`, so it embeds whatever is in
`internal/run/agents`: nothing on a fresh checkout, or possibly stale agents.

To exercise a change on real hosts, follow the instructions at the top of
`test/containers/up.sh`. It needs a Docker daemon that allows `--privileged`.

## Rules

- Bump `host.ProtocolVersion` whenever a message or resource changes. `Hello`
  and `Upgrade` must never change shape, so any controller can upgrade any agent.
- Keep `completions/` in step with the commands and flags in `cmd/sensible`.
- Features must handle both Debian and Arch hosts.
