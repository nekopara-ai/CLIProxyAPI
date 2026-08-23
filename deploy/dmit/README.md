# DMIT fork deployment

This directory contains the production updater for the DMIT CLIProxyAPI service.
It deliberately trusts only stable releases from `nekopara-ai/CLIProxyAPI` and
does not use CLIProxyAPI's built-in upstream release source.

## Release contract

The latest release must use `vX.Y.Z-nekopara.N`, point to a lightweight commit
tag, and contain exactly one expected Linux amd64 archive plus
`checksums.txt` and `build-info.json`. The updater cross-checks the GitHub asset
digests, both checksum entries, release tag commit, build metadata, archive
members, ELF architecture, interpreter, maximum GLIBC version, and the version
and commit reported by the candidate binary. The release workflow also creates
GitHub/Sigstore build-provenance attestations for all three release assets.

Normal scheduled runs require an `installed.json` written by a successful
manual bootstrap. This prevents an unattended timer from changing the trusted
release source on first installation. An equal version with a changed commit or
asset digest is rejected, and a candidate that requires rollback is quarantined.

## Transaction and recovery behavior

The updater holds `/run/lock/cliproxyapi-fork-update.lock` for the entire run,
backs up the live binary, config, systemd unit, and drop-ins, then replaces the
binary with a same-filesystem atomic rename. It verifies the local model catalog
and real non-streaming and streaming `/v1/responses` requests. The streaming
probe requires `response.completed`.

Any failure after replacement restores the verified backup. Persistent
transaction state covers power loss. The recovery unit is a boot latch ordered
before `cliproxyapi.service`; the CPA drop-in requires that latch. The updater
service also runs `--poststop`, so a killed or timed-out updater is recovered
without waiting for the next reboot.

Request and response bodies, API keys, and environment contents are never
written to updater output. The probe emits only model count, selected public
model name, timing, and fixed error classifications.

## Installation order

Install the two executables, three units, and CPA drop-in. Then run:

```text
systemctl daemon-reload
systemctl enable --now cliproxyapi-fork-recover.service
/usr/local/sbin/cliproxyapi-fork-update --check
/usr/local/sbin/cliproxyapi-fork-update --bootstrap
systemctl enable --now cliproxyapi-fork-update.timer
```

The recovery service must be `active (exited)` before bootstrap. Never bypass
the updater with a direct binary copy. Backups, stages, quarantine records, and
audit logs are retained for manual inspection; no automatic cleanup runs.
