# Signal Infiltrator Check

A small, dependency-free Python tool that checks whether a watchlist of Signal
**safety-number halves** (individual numeric fingerprints) appears among the
members of the Signal groups your account belongs to — even if those accounts
have since renamed themselves.

The use case it was built for: a set of accounts gets publicly flagged (for
example, infiltrators of organizing chats), and you want to know whether any of
them are sitting in *your* groups. Because the check is keyed to an account's
cryptographic identity rather than its display name, a rename, username change,
or phone-number change won't evade it.

---

## What it does — and what it doesn't

**It does:**

- Pull your groups (with members) and known identities from
  [`signal-cli`](https://github.com/AsamK/signal-cli).
- Auto-detect *your* half of each safety number and subtract it out.
- Compare every resolvable group member's half against a watchlist you supply.
- Report matches, the watchlist entries that never matched, and coverage gaps.

**It does not:**

- De-anonymize anyone, reveal phone numbers, or link separate accounts to a
  single person. A safety-number half is a hash of one account's identity key;
  two accounts run by the same operator have two unrelated halves.
- Prove wrongdoing. A match means *"this is the same identity key that was
  flagged"* — it is a lead for your own judgment, not a verdict. The original
  identification could itself be wrong, so confirm through a second signal
  before anyone is named or removed.

---

## How it works

A Signal safety number is a **sorted concatenation of two 30-digit individual
fingerprints**: yours and the other party's. Each half is derived only from that
party's identity key plus their account identifier (ACI), so the *other* party's
half is identical in every conversation they are in — it does not depend on who
they are talking to. That is what makes a posted half usable as a cross-chat
account identifier.

This tool finds the 30-digit block common to all of your safety numbers (that's
your half), subtracts it, and matches the remaining half of each group member
against your watchlist. The match holds until the flagged account generates a
**new identity key** — i.e. on reinstall or re-registration. A rename does not
break it; a fresh install does.

---

## Background: what is signal-cli?

`signal-cli` is an **unofficial** command-line / JSON-RPC / D-Bus interface for
Signal, maintained by [AsamK](https://github.com/AsamK/signal-cli). It registers
or links as a normal Signal device and performs the actual protocol and crypto
through Signal's own `libsignal` libraries, so it is not a re-implementation of
the encryption — the cryptographic core is Signal's code, and AsamK's project is
the surrounding glue (account management, storage, the CLI).

Two things worth knowing up front:

- **Keep it current.** Official Signal clients expire after about three months,
  after which Signal-Server can make incompatible changes. `signal-cli` releases
  older than ~3 months may stop working. Update periodically.
- **It is a linked device.** Whatever runs `signal-cli` can read your future
  messages and act as your account, and it stores its keys unencrypted at rest.
  Treat it as sensitive (see [Security notes](#security-notes)).

---

## Requirements

- **Python 3.8+** (standard library only — nothing to `pip install`).
- **signal-cli**, which needs a **Java Runtime Environment, version 21 or newer**
  (older systems can use a JRE 17 build of signal-cli).
- A Signal account **linked to signal-cli** — specifically the account whose
  groups you want to check.

The native libraries signal-cli depends on are bundled in the official releases
for x86-64 Linux (recent glibc), Windows, and macOS, so on those platforms you
do not need to build anything.

---

## Installing signal-cli

### Java (all platforms)

Install a JRE/JDK 21+ if you don't have one. [Eclipse Temurin / Adoptium](https://adoptium.net)
provides builds for every platform. Verify with:

```
java -version
```

### Linux

**Option A — Flatpak (recommended; it runs sandboxed):**

```bash
flatpak install flathub org.asamk.SignalCli
# invoke as:  flatpak run org.asamk.SignalCli ...
```

**Option B — official tarball:**

```bash
export VERSION=<latest, e.g. 0.13.x>   # see the releases page for the current tag
wget https://github.com/AsamK/signal-cli/releases/download/v"${VERSION}"/signal-cli-"${VERSION}".tar.gz
sudo tar xf signal-cli-"${VERSION}".tar.gz -C /opt
sudo ln -sf /opt/signal-cli-"${VERSION}"/bin/signal-cli /usr/local/bin/
```

**Option C — package managers:** community packages exist (Arch AUR, a Docker
image, etc.), and `brew install signal-cli` works on Linux as well.

> On headless/idle machines, signal-cli may block waiting for entropy. Installing
> an entropy daemon such as `haveged` resolves it.

### macOS

```bash
brew install signal-cli   # pulls in a suitable Java automatically
```

### Windows

1. Install a JRE 21+ (Temurin from Adoptium).
2. Download the latest release archive from the
   [releases page](https://github.com/AsamK/signal-cli/releases) and unpack it,
   e.g. to `C:\signal-cli`.
3. Run it from the `bin` folder using the batch launcher:

```bat
C:\signal-cli\bin\signal-cli.bat --version
```

Alternatively, install [WSL2](https://learn.microsoft.com/windows/wsl/) and
follow the **Linux** instructions inside your WSL distribution — often the
smoother path on Windows.

### Confirm it runs

```
signal-cli --version
# Flatpak:  flatpak run org.asamk.SignalCli --version
# Windows:  C:\signal-cli\bin\signal-cli.bat --version
```

---

## Linking your Signal account

You must link the account **with the same signal-cli installation you'll run the
tool through** — a Flatpak instance keeps its data inside its sandbox
(`~/.var/app/org.asamk.SignalCli/`) and will not see an account you linked with a
host binary, and vice versa.

```bash
# Linux/macOS host binary:
signal-cli -a +15551234567 link -n audit

# Flatpak:
flatpak run org.asamk.SignalCli -a +15551234567 link -n audit

# Windows:
C:\signal-cli\bin\signal-cli.bat -a +15551234567 link -n audit
```

This prints a `sgnl://linkdevice...` URI; render it as a QR code and scan it from
**Signal → Settings → Linked Devices** on your phone. The phone number must be in
international format, starting with `+` and the country code.

When you're done auditing, remove the device again from that same Linked Devices
screen.

---

## Usage

The watchlist is a plain text file with **one 30-digit safety-number half per
line**. Spaces are ignored (so you can paste the grouped form), and blank lines
and lines starting with `#` are skipped:

```
# infiltrator halves
99900 00000 00000 00000 00000 00777
88812 34500 00000 00000 00000 00044
```

The Python script runs on the host and only reads signal-cli's **stdout**, plus
its own files (the watchlist, optional JSON inputs, optional report). It never
asks the sandbox to open your files — which is why a network-only Flatpak profile
is enough on Linux.

### Linux

```bash
chmod +x signal_infiltrator_check.py

# host binary on PATH:
./signal_infiltrator_check.py watchlist.txt -a +15551234567 --receive

# via the hardened Flatpak:
./signal_infiltrator_check.py watchlist.txt -a +15551234567 --flatpak --receive
```

### macOS

```bash
python3 signal_infiltrator_check.py watchlist.txt -a +15551234567 --receive
```

### Windows

`signal-cli` on Windows is a `.bat` launcher, which Python's subprocess won't
auto-discover by bare name, so point `--signal-cli` at the full path:

```bat
py signal_infiltrator_check.py watchlist.txt -a +15551234567 ^
   --signal-cli "C:\signal-cli\bin\signal-cli.bat" --receive
```

### Cross-platform fallback (no subprocess at all)

Run signal-cli yourself to dump the two JSON files, then feed them in. This
behaves identically on every platform and sidesteps the Windows `.bat` issue and
any locked-account-directory problems:

```bash
signal-cli -a +15551234567 --output=json listIdentities > ids.json
signal-cli -a +15551234567 --output=json listGroups -d  > grps.json

python3 signal_infiltrator_check.py watchlist.txt \
    --identities-json ids.json --groups-json grps.json
```

---

## Output and exit codes

The tool prints a human-readable report: the matches and where they were found,
the watchlist entries with no match, members whose identity key it couldn't
resolve (blind spots, **not** cleared), and any skipped watchlist lines.

- Exit code **1** if one or more matches were found (pipeline-friendly).
- Exit code **0** if none matched.
- `--report-json PATH` additionally writes a machine-readable report.

---

## Options

| Flag | Purpose |
|------|---------|
| `watchlist` | Path to the watchlist file (one 30-digit half per line). **Required.** |
| `-a`, `--account` | Your signal-cli account, e.g. `+15551234567`. |
| `--flatpak` | Invoke signal-cli via `flatpak run` instead of a host binary. |
| `--flatpak-app` | Flatpak application id (default `org.asamk.SignalCli`). |
| `--signal-cli` | Path to the signal-cli binary (or `.bat` on Windows). |
| `--my-half` | Override auto-detection of your own 30-digit half. |
| `--receive` | Run `signal-cli receive` first to populate more identities. |
| `--identities-json` | Read `listIdentities` JSON from a file instead of calling signal-cli. |
| `--groups-json` | Read `listGroups -d` JSON from a file instead of calling signal-cli. |
| `--report-json` | Also write a machine-readable report to this path. |

---

## Caveats and limitations

Please read these — they determine how much a result is worth.

- **Identity key, not persona.** Renames, usernames, and number changes don't
  evade the check; a reinstall or re-registration (new identity key) does. Treat
  a non-match as *weak* evidence of absence, and refresh the watchlist if time
  has passed.
- **Identifier basis must match.** If the watchlist halves were captured on a
  different basis (legacy phone-number-based vs. current ACI-based safety
  numbers) than your account computes, the *same* account yields a different half
  and silently won't match. If you have one account you can independently confirm
  should be present, use it as a positive control to validate the whole list.
- **Unresolved members are blind spots, not clearances.** The tool can only
  compare members whose identity key signal-cli already knows. Run with
  `--receive` to populate more; the report counts the rest so you can see the
  gap honestly.
- **A match is a lead, not proof.** It confirms the key, not the intent, and not
  even the original accusation. Verify before acting.

---

## Security notes

- `signal-cli` stores its account keys **unencrypted at rest**. Anything able to
  read its data directory can clone the account onto another machine and run a
  silent parallel session. Rely on full-disk encryption, keep the data directory
  permissions tight, and prefer running this inside a sandbox or a dedicated VM.
- A linked device is a **standing credential**. Link it, run the audit, and
  unlink it when you're done rather than leaving it in place.
- On Linux, the Flatpak can be hardened to **network-only** (no filesystem, no
  IPC) because the script reads signal-cli over stdout and does its own file I/O.
  Flatpak's network permission is all-or-nothing, so per-domain egress limiting
  (to `*.signal.org`) must be done at the network layer — a host/edge firewall
  or, more cleanly, a per-VM firewall.

---

## License

MIT License. Provided as-is, with no warranty.

Use it only on groups you belong to or administer, and remember that the output
is investigative input, not an accusation.
