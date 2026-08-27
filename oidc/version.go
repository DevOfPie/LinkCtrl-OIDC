package oidc

// Name is this add-on's name, and it is three things at once: the directory an
// operator installs it into, the Postgres schema the host gives it, and the
// route prefix `/addons/oidc/` its pages are served under. The host derives all
// three from the manifest's `name`, so this constant and that field are one fact
// in two files and a test asserts they agree.
const Name = "oidc"

// Version is this add-on's own release, which the ABI is explicit is its
// author's business and not the product's: only the boundary is versioned there.
// It is in the manifest, on the status page and in CHANGELOG.md, and a test
// asserts the first two agree.
const Version = "0.1.0"
