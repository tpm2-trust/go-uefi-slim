# uefi

UEFI for Go programs on Linux, with the standard library and `golang.org/x/sys`
alone: EFI variables through efivarfs, and (to come) Secure Boot's signature
databases, signed variable updates and Authenticode. What it writes is what
sbctl writes, so either can take over a machine the other set up.

Used by aSSH (`persist`: its CA in an EFI variable) and tpm2-kira (its own
variables, Secure Boot). Part of the tpm2-trust workspace; owned by neither
project.

## efivar

```go
s := efivar.Store{}                       // efivarfs at /sys/firmware/efi/efivars
attrs, data, err := s.Read("SecureBoot", efivar.GlobalVariable)
err = s.Write("Name", guid, efivar.NonVolatile|efivar.BootServiceAccess|efivar.RuntimeAccess, data)
err = s.Remove("Name", guid)              // os.ErrNotExist when there is none
on, err := s.ReadBool("SetupMode", efivar.GlobalVariable)
```

- **One write, whole.** efivarfs replaces a variable with each write and takes
  it whole or not at all; the file is opened with `O_TRUNC` (efivarfs ignores
  it; a directory standing in for efivarfs needs it), `O_APPEND` with
  `AppendWrite`. An empty write is refused (`ErrEmpty`): efivarfs takes it as
  a removal.
- **The immutable mark.** efivarfs marks most variables immutable against an
  accidental `rm`. A write or a removal lifts the mark and puts it back
  afterwards, also when it failed. Looking at a variable never creates it.
- **`Store{Dir: ...}`** stands a directory in for efivarfs: tests, a chroot.

## Tests

`go test -count=1 ./...`. The immutable test needs `CAP_LINUX_IMMUTABLE` and
is skipped without it; run the test binary as root on a machine (tmpfs has
the bit since Linux 6.0). `go test -fuzz` for the parsers.

## Licence

BSD 3-Clause.
