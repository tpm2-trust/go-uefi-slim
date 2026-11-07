# Notes for agents working on go-uefi-slim

- **The standard library and `golang.org/x/sys` alone.** No other dependency:
  aSSH and kira link this, and safearch's initrd links aSSH. PKCS#7,
  signature lists, Authenticode are built with `encoding/asn1`, `crypto/x509`,
  `debug/pe`.
- **Not go-uefi's code.** Nothing is copied from foxboron/go-uefi (MIT); this
  module is BSD-3 and written from the specifications, edk2 and sbctl's
  output.
- **sbctl can take over.** Whatever this writes (variables, signature lists,
  signed updates, signatures in a PE) is what sbctl writes and reads; tests
  check against sbctl's and sbsigntools' output where there is one.
- **Never create by looking, never leave the immutable mark lifted.** A check
  opens read-only; a write or removal puts the mark back, also after a failure.
- **Nothing project-specific.** No name, GUID or path of aSSH's or
  kira's: they pass their own.
- **No backwards compatibility** (the workspace's rule): one API, the current.
- **Tests run with `-count=1`, wait for a state, never for a time.** Parsers of
  outside input (signature lists, PE files) have fuzz targets.
- **Comments and docs say what it is**, not what it was.
