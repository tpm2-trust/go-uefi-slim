# uefi

UEFI for Go programs on Linux, with the standard library and `golang.org/x/sys`
alone: EFI variables through efivarfs, Secure Boot's signature databases,
signed variable updates and Authenticode. What it writes is what sbctl,
sbsigntools and efitools write, so either can take over a machine the other
set up.

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

## sigdb, authvar, authenticode, mscerts: Secure Boot

```go
db := sigdb.Database{sigdb.X509(owner, cert)}           // EFI_SIGNATURE_LISTs
data, _ := db.Bytes()
upd, _ := authvar.Sign(authvar.DB, authvar.Attributes, data, kekKey, kekCert, time.Now())
err = efivar.Store{}.Write("db", efivar.ImageSecurityDatabase, authvar.Attributes, upd)
signed, _ := authenticode.Sign(img, dbKey, dbCert)       // a boot loader, a UKI
err = authenticode.Verify(signed, dbCert)
kek, _ := mscerts.KEK()                                  // Microsoft's, as sbctl --microsoft
```

- **sigdb**: EFI_SIGNATURE_LIST read and built, every type of the UEFI
  specification (X.509; SHA-1/224/256/384/512 and SM3 digests; RSA-2048 keys
  and signatures; X.509 To-Be-Signed digests with their revocation time;
  external management), each held to its size and to no header; a type the
  specification does not define is kept as it is. The lists are byte for
  byte what efitools' `cert-to-efi-sig-list` makes; Microsoft's published dbx
  updates read and write back unchanged. SM3 digests are given, not computed
  (Go's standard library has no SM3).
- **authvar**: EFI_VARIABLE_AUTHENTICATION_2 - a PKCS#7 SignedData (no
  ContentInfo, detached, with signed attributes, as sbctl) over the variable's
  name, GUID, attributes, timestamp and data. Verifies updates with or without
  signed attributes (efitools' `sign-efi-sig-list` has none).
- **authenticode**: the image hash as the firmware computes it (edk2), the
  signature appended as an 8-byte aligned WIN_CERTIFICATE, the checksum set;
  `sbverify` accepts what it signs, and it verifies what `sbsign` signs.
- **mscerts**: Microsoft's KEK and db certificates (2011, 2023), downloaded
  from Microsoft, identical to sbctl's copy, pinned by SHA-256 in the test.

Keys sign through `crypto.Signer`: a key file, a YubiKey, the TPM. UEFI
signatures are RSA.

## Tests

`go test -count=1 ./...`. The immutable test needs `CAP_LINUX_IMMUTABLE` and
is skipped without it; run the test binary as root on a machine (tmpfs has
the bit since Linux 6.0). `go test -fuzz` for the parsers (signature lists,
signed updates, PE images). Checked once against sbsigntool and efitools
(2026-10-30, Debian trixie): see the commit log.

## On a machine's firmware

`internal/vmcheck` tries the module on firmware in Setup Mode (a test VM:
enrolling PK ends Setup Mode for good). `vmcheck enrol /var/lib/sbctl
FILE...` makes PK, KEK and db as sbctl lays them out (RSA-4096), signs the
files, enrols db, KEK and PK with Microsoft's certificates; `vmcheck state`,
`vmcheck verify`. Done on tpm2-kira's local VMs (OVMF with Secure Boot,
2026-10-30):

- Arch (systemd-boot, a UKI, both signed here): boots with Secure Boot on;
  `sbctl status` reads the keys as its own (owner GUID, vendor keys
  microsoft), `sbctl verify` the files as signed; a UKI changed by one byte
  is refused by the firmware ("Access denied").
- Debian (shim, GRUB): boots with Secure Boot on through Microsoft's
  certificates as enrolled here.

## Licence

BSD 3-Clause.
