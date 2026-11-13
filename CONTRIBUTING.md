# Contributing

## Set up

```sh
curl -fsSL https://pixi.sh/install.sh | sh
pixi install
pixi run check
```

`pixi run check` formats-checks, lints docstrings, precompiles the package
and runs every unit test. `pixi run -e interop interop` additionally runs
the go-nethernet interop matrix and installs Go for it.

Optional: `pixi x pre-commit install` formats and lints on every commit.

## Ground rules

- Read [AGENTS.md](AGENTS.md). It is written for coding agents, but the
  architecture rules, the quality bar and the Mojo 1.2 pitfalls apply to
  everyone.
- Every behaviour change comes with a test. A bug fix comes with a test that
  fails without it.
- A change to anything on the wire needs an interop run. If it changes what
  go-nethernet sees, say so in the pull request.
- Cryptographic code needs published test vectors and a statement of which
  operations are constant-time.
- Keep pull requests focused, and describe why the change is needed.

## Layout

```text
src/nethernet/     the package; see docs/architecture.md
test/nethernet/    one test_<module>.mojo per module, same tree as src
benchmarks/        bench_<module>.mojo, same tree as src
examples/          programs with a main()
interop/           the go-nethernet harness and its runner
docs/              architecture, protocol and interop notes
```

## Releasing

1. Update `version` in `pixi.toml` and add a section to `CHANGELOG.md`.
2. Tag `v<version>`.
3. To publish to the `modular-community` conda channel, open a pull request
   there with `conda.recipe/recipe.yaml` pointing at the tagged commit.
