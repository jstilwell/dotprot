<div align="center">

# 🔒 dotprot

**Pick up where you left off without worrying about your `.env` files.**

Lock your `.env` (and anything else you list) into a dedicated 1Password vault,
then restore it on demand. dotprot uploads the exact bytes, **verifies the copy
round-trips correctly, and only then removes the file from disk.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org)
[![Buy me a coffee](https://img.shields.io/badge/%E2%98%95-Buy%20me%20a%20coffee-ffdd00.svg)](https://buy.stripe.com/5kQ4gBe7Lc7s68YaqZ4F200)

</div>

---

## Why?

As a software engineer, I like using `.env` files but my paranoia doesn't allow for me to leave a bunch of .env files on my disk without worrying about it. I'm a big fan of the [1Password](https://1password.com/) password manager and I use its [CLI tool](https://1password.com/downloads/command-line) extensively. So I thought, why not use a 1Password vault to store my `.env` files as file attachments? Then it just felt like a no-brainer to create a little easy-to-use wrapper for 1Password CLI to lock `.env` files away inside of a 1Password vault and then retrieve them when I'm ready to work again.

## Quickstart

- [Install dotprot](#install)
- Change directory to any directory with a `.env` file.
  - If you don't use `.env` then type `dotprot setup` and add your file(s) to `.prot`
- Sign in to 1Password via `op signin`
- Type `dotprot`

```shell
Created .prot (protecting: .env*).
Created 1Password vault ".prot" (6djqbcxlh235372hbuvtuqnr4i).
(one-time setup — future runs reuse it)
  locked .env -> 1Password
Locked 1 file(s) into vault ".prot".
```

- Type `ls -a`
- Notice `.env` is no longer there.
- Check your brand new `.prot` vault in 1Password
- 🎉 There it is!
- Type `dotprot` again to bring your .env file back. (A copy stays behind in 1Password)

## Contents

- [🔒 dotprot](#-dotprot)
  - [Why?](#why)
  - [Quickstart](#quickstart)
  - [Contents](#contents)
  - [How it works](#how-it-works)
  - [Requirements](#requirements)
  - [Install](#install)
    - [Homebrew](#homebrew)
    - [Cargo](#cargo)
    - [npm](#npm)
    - [Prebuilt binaries](#prebuilt-binaries)
    - [From source](#from-source)
  - [Usage](#usage)
    - [The toggle](#the-toggle)
    - [Trying it safely with `--keep`](#trying-it-safely-with---keep)
  - [The `.prot` file](#the-prot-file)
  - [`.prot` backups and `dotprot restore`](#prot-backups-and-dotprot-restore)
  - [Safety guarantees](#safety-guarantees)
  - [Development](#development)
  - [License](#license)

## How it works

dotprot reads a `.prot` file in your working directory that lists which files to
protect — globs, one per line, defaulting to `.env*`. Each protected file is
stored as a 1Password **document** in a vault named `.prot`. The document IDs are
written back into your `.prot` file so the same directory can lock and unlock
repeatedly.

```
┌─────────────┐   dotprot lock    ┌──────────────────────┐
│  ./.env     │ ────────────────► │  1Password ".prot"   │
│  (on disk)  │ ◄──────────────── │  vault (documents)   │
└─────────────┘   dotprot unlock  └──────────────────────┘
```

## Requirements

- The [1Password CLI (`op`)](https://developer.1password.com/docs/cli/get-started/),
  signed in (`op signin`).

dotprot never touches your 1Password credentials — it shells out to `op`, which
handles all authentication. If you're not signed in when you run a command,
dotprot offers to sign you in: at an interactive terminal it asks
`Sign in now? [y/N]` and, on yes, runs `op signin` for you (Touch ID, the
desktop-app approval, or an account prompt — whatever your setup uses) before
continuing. In a non-interactive context (CI, a pipe), it doesn't prompt — it
prints `Run \`op signin\` first.` and exits without doing anything.

## Install

### Homebrew

```sh
brew install jstilwell/tap/dotprot
```

### Cargo

```sh
cargo install dotprot
```

### npm

```sh
npm install -g dotprot
```

Installs a prebuilt binary for your platform (no Rust toolchain needed). One-off
runs work too: `npx dotprot`.

### Prebuilt binaries

Download the binary for your platform from the
[releases page](https://github.com/jstilwell/dotprot/releases) and put it on
your `PATH`.

### From source

```sh
git clone https://github.com/jstilwell/dotprot
cd dotprot
cargo build --release      # binary at target/release/dotprot
```

## Usage

```sh
dotprot           # smart toggle: lock if files present, unlock if absent
dotprot lock      # force lock:   upload → verify → delete from disk
dotprot unlock    # force unlock: restore files from 1Password
dotprot restore   # recover this directory's .prot from its local backup
dotprot --keep    # lock, but keep the originals on disk (don't delete)
dotprot setup     # optional: pre-create the .prot vault in 1Password
```

You don't have to run `dotprot setup` first. The very first `dotprot` (or
`dotprot lock`) in a directory creates the `.prot` vault automatically if it
doesn't exist, tells you it did, and carries on:

```text
$ dotprot
Created 1Password vault ".prot" (abc123...).
(one-time setup — future runs reuse it)
Created .prot (protecting: .env*).
  locked .env -> 1Password
Locked 1 file(s) into vault ".prot".
```

### The toggle

Running bare `dotprot` figures out which way to go from what's on disk:

| State                                  | What `dotprot` does                                                   |
| -------------------------------------- | --------------------------------------------------------------------- |
| Protected files are **present**        | Locks them into 1Password                                             |
| Protected files are **missing**        | Restores them from 1Password                                          |
| **Mixed** (some present, some missing) | Stops and asks you to be explicit (`dotprot lock` / `dotprot unlock`) |

Template files (`.env.example` and friends — see below) don't count toward this
decision, even if an older `.prot` still records one as a document. They belong
on disk, so the toggle ignores them rather than reading a project with locked
secrets and a checked-in `.env.example` as a "mixed" state.

### Trying it safely with `--keep`

Before trusting dotprot to delete anything, upload-and-verify without removing
the originals:

```sh
dotprot --keep    # .env is copied to 1Password and verified, but stays on disk
# open the .prot vault in the 1Password app and confirm .env is there
dotprot lock      # now remove the local copy
```

## The `.prot` file

Auto-created on first lock. dotprot owns everything above the sentinel and
rewrites it freely; the file list below the sentinel is yours to edit:

```text
# dotprot — managed below, do not edit
vault: abcd1234efgh5678
doc .env: 6yx...
doc config/secrets.json: q9z...
# ---- your files (edit below) ----
.env*
config/secrets.json
```

> **Tip:** commit `.prot` to version control. It contains only 1Password
> vault/item IDs — **no secrets** — and lets teammates `dotprot unlock` the same
> files, given access to the vault.

### Template files are not swept up by globs

Glob patterns skip files whose name ends in `.example`, `.sample`, `.template`,
or `.dist` — so the default `.env*` protects `.env` and `.env.local` but leaves
`.env.example` alone, since template files hold no secrets and are meant to
stay in the repo. dotprot prints a `skip` line when this happens. In the rare
case such a file really does contain secrets, list it by its exact name in
`.prot` (e.g. a literal `.env.example` line) and it will be protected.

## `.prot` backups and `dotprot restore`

`.prot` is the map from your (deleted) files back to their 1Password documents,
so losing it is the one local mistake that hurts. Every time dotprot writes a
`.prot`, it also mirrors it to a per-project backup in your home directory:

```text
~/.prot/backups/<absolute project path>/.prot
# e.g. /Users/you/code/myapp  →  ~/.prot/backups/Users/you/code/myapp/.prot
# on Windows: C:\Users\you\code\myapp  →  C:\Users\you\.prot\backups\C\Users\you\code\myapp\.prot
```

Deleted your `.prot` by accident? From the project directory:

```sh
dotprot restore   # copies the backup back; then `dotprot unlock` as usual
```

`restore` is purely local (no 1Password sign-in needed) and cautious: if a
`.prot` already exists it never overwrites it — it tells you when the two
already match, and refuses when they differ. Like `.prot` itself, backups
contain **no secrets**, only vault/document IDs and your file patterns. A
backup that can't be written (say, an unwritable home directory) prints a
warning but never blocks a lock.

## Safety guarantees

dotprot's whole reason to exist is to make secrets _easier_ to manage, never to
put them at risk. The design centers on one rule: **a local file is deleted only
after a verified, recoverable copy exists in 1Password.**

- **Verify-then-delete.** A file is removed from disk only after its 1Password
  copy is uploaded, **read back, and confirmed byte-identical**. The file is
  also re-read immediately before deletion — if it changed while the upload was
  in flight, it's left in place (the vault copy would be stale). Any failure in
  that chain leaves the original untouched. Use `--keep` to skip deletion
  entirely.
- **Scoped to the `.prot` vault only.** Every 1Password operation is scoped with
  `--vault .prot`. dotprot **never deletes 1Password items in normal
  operation** — lock creates/updates documents, unlock only reads them. The
  vault ID recorded in `.prot` is verified to still be the vault named `.prot`
  before every run, so a stale or tampered ID can't point writes at another
  vault in your account.
- **Incremental persistence.** `.prot` is updated after _each_ file locks, so an
  interruption mid-batch leaves you in a consistent, recoverable state. Each
  update is written atomically (temp file + rename), so even a crash mid-write
  can't corrupt the recorded document IDs.
- **Backups are kept.** Documents stay in 1Password after unlock, so a directory
  stays re-lockable and you always have a copy. Re-locking overwrites the
  existing document in place. `.prot` itself is mirrored to
  `~/.prot/backups/…` on every write, and `dotprot restore` brings it back if
  it's ever lost.
- **Stable titles.** Document titles are the file's **absolute path**, so
  they're easy to find in the 1Password UI and never collide across directories
  or machines.
- **Restores stay inside the project.** `unlock` accepts only plain relative
  `.prot` entry paths (no absolute or rooted paths, no `..`), validates every
  recorded path before restoring anything, and never writes through a symlink
  (even a dangling one) — a tampered or malicious `.prot` can't redirect a
  restored secret elsewhere on disk.
- **No silent skips.** A pattern match that can't be safely locked — a file
  outside the working directory, or a filename that `.prot`'s format can't
  record faithfully — is skipped **with a loud warning**, never silently, so a
  secret is never left in plaintext while you believe it's protected.
- **Minimal on-disk exposure.** Secrets are handed to `op` via a short-lived
  `0600` temp file that's deleted immediately afterward (the 1Password CLI does
  not reliably accept piped stdin). Restored files and the `.prot` state file are
  also written `0600` (newly created ones; an existing `.prot`'s mode is left as
  you set it).

> **Platform note (Windows):** the owner-only (`0600`) file-permission hardening
> is currently enforced on **macOS and Linux only**. On Windows the temp and
> restored files are created with default ACLs. The verify-then-delete guarantee
> and vault scoping hold on all platforms; only the file-permission tightening is
> Unix-only for now. See [CHANGELOG.md](CHANGELOG.md).

## Development

```sh
cargo build            # debug build
cargo test             # run unit tests
cargo clippy           # lint
cargo build --release  # optimized binary
```

See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

[MIT](LICENSE)
