# Proposed workflows

Changes to `.github/workflows/` are written here and applied by the owner. This
mirrors [LinkCtrl](https://github.com/DevOfPie/LinkCtrl)'s `ci/proposed/`, at the
owner's instruction on 2026-08-27 — *"I will also need to make any changes to CI
so follow the same workflow as LinkCtrl"* — and for the same reason.

## Why a proposal and not a commit

The token the agent building this repository holds has no `Workflows`
permission, and that is deliberate rather than an oversight to be corrected: it
is the one permission that would let a token rewrite the file deciding what runs
on a runner. GitHub refuses the **push**, not the merge, so a branch carrying a
workflow file cannot reach the remote at all.

This repository has two further protections the agent does not bypass and should
not be given a bypass for: **main branch protection**, and **tag protection** on
`~ALL` for creation and update. So the agent writes code and tests, and the owner
applies workflows and cuts tags.

## What is waiting

| File | What it is | Applied |
| --- | --- | --- |
| `ci.yml` | Build to wasm, run the tests, run `scripts/sabotage.sh`, and build the artifact **twice in two places** — once in the checkout and once from a `git archive` — asserting the digests match | **No** |
| `release.yml` | On a tag: build the bundle, attach it with its checksum, and run `attest-build-provenance` | **No** |

Neither has ever run. Until `ci.yml` is applied this repository's *CI green*
gate is unmet, and the tests are green only where somebody ran them by hand.

## Applying them

```sh
mkdir -p .github/workflows
cp ci/proposed/ci.yml ci/proposed/release.yml .github/workflows/
git add .github/workflows && git commit -m "Apply the proposed workflows"
git push origin main
```

Then mark the rows above **Yes** in the same commit or the one after, so this
file does not describe a proposal that has already landed.

## The tag, which is the other half

`v0.1.0` cannot be created by the agent. Its content is reproducible and its
digests are recorded in `CHANGELOG.md`; cutting it is:

```sh
git tag -a v0.1.0 -m "v0.1.0" && git push origin v0.1.0
```

**`release.yml` must be applied first**, or the tag lands with nothing watching
for it and the release carries no artifact and no provenance.

## Why the build runs twice, in two places

Go stamps the VCS revision and a `vcs.modified` flag into a main package built
inside a checkout, so the same source produced **different bytes** from a
`git archive` tarball than from the tree it came out of. A digest nobody else can
reproduce proves nothing, which is the whole point of publishing one. `ci.yml`
builds both ways and compares, and the module build carries `-buildvcs=false`.
