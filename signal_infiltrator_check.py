#!/usr/bin/env python3
"""
signal_infiltrator_check.py

Check whether a watchlist of Signal "safety-number halves" (individual numeric
fingerprints) appears among the members of the Signal groups your signal-cli
account belongs to.

HOW THIS WORKS
--------------
A Signal safety number is a *sorted concatenation of two 30-digit individual
fingerprints*: yours and the other party's. Each half is derived only from that
party's identity key + account identifier (ACI), so the other party's half is
identical in every conversation they are in -- it does NOT depend on who they
are talking to. That is what makes a posted "half" usable as a cross-chat
account identifier.

This script:
  1. Pulls your groups (with members), your known identities, and your contacts
     from signal-cli (or from JSON files you dump yourself).
  2. Auto-detects YOUR half -- the 30-digit block common to all your safety
     numbers -- so we can subtract it out. (Override with --my-half if needed.)
  3. For each group member whose identity key signal-cli already knows, extracts
     THEIR half and compares it to your watchlist.
  4. Reports matches, resolving each to a human label (profile name / username /
     number) plus the rename-proof ACI, and prints a ready-to-run removal command.
     With --remove, it can remove (and optionally --ban) matched members from
     groups your linked account administers.

IMPORTANT CAVEATS (please actually read)
----------------------------------------
* This matches an identity KEY, not a persona. A rename, username change, or even
  a phone-number change does NOT evade it. But a reinstall / re-registration
  generates a NEW identity key -> a stale watchlist will silently stop matching.
  Move fast, and treat a non-match as weak evidence, not an all-clear.
* It is only as good as the watchlist. If those halves were captured on a
  different identifier basis (legacy phone-number-based vs current ACI-based
  safety numbers), the SAME account will produce a different half and won't match.
* A match means "this is the same key that was flagged," NOT proof of wrongdoing.
  The original identification could be wrong. Treat a hit as a lead for your own
  judgment, especially before removing or naming anyone.
* It only covers the groups this account is in, and only members whose identity
  key signal-cli has already received. Unresolved members are reported so you can
  see the blind spots; run with --receive (or `signal-cli receive`) first to
  populate more of them.

USAGE
-----
  # Straight through signal-cli:
  ./signal_infiltrator_check.py watchlist.txt -a +15551234567 --receive

  # Via the hardened Flatpak (signal-cli runs in its sandbox; this script stays
  # on the host and only reads its stdout, so the sandbox needs no file access):
  ./signal_infiltrator_check.py watchlist.txt -a +15551234567 --flatpak --receive

  # Or dump the JSON yourself and feed it in (useful if the account dir is busy):
  signal-cli -a +1555... --output=json listIdentities  > ids.json
  signal-cli -a +1555... --output=json listGroups -d   > grps.json
  ./signal_infiltrator_check.py watchlist.txt --identities-json ids.json --groups-json grps.json

watchlist.txt: one 30-digit half per line. Spaces are ignored, so you can paste
the grouped form. Blank lines and lines starting with # are skipped.
"""

import argparse
import json
import re
import shlex
import subprocess
import sys
from collections import Counter, defaultdict


# ---------- small helpers ----------

def _first(d, *keys, default=None):
    """Return the first present, non-empty value among candidate keys."""
    if not isinstance(d, dict):
        return default
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return default


def digits_only(s):
    return re.sub(r"\D", "", s or "")


def split_halves(safety_number):
    """Return (first30, second30) digit strings, or None if not exactly 60 digits."""
    d = digits_only(safety_number)
    if len(d) != 60:
        return None
    return d[:30], d[30:]


# ---------- signal-cli I/O ----------

def build_launcher(args):
    """Return the command prefix used to invoke signal-cli.

    Host binary:  ["signal-cli"]              (or whatever --signal-cli points at)
    Flatpak:      ["flatpak", "run", APP_ID]  (everything after APP_ID is passed
                                               straight through to signal-cli)
    """
    if args.flatpak:
        return ["flatpak", "run", args.flatpak_app]
    return [args.signal_cli]


def _launch_hint(launcher):
    if launcher[:2] == ["flatpak", "run"]:
        app = launcher[2] if len(launcher) > 2 else "org.asamk.SignalCli"
        return ("Is flatpak installed and the app present?  Try:\n"
                f"  flatpak install --user flathub {app}")
    return "Install signal-cli, pass --signal-cli /path/to/signal-cli, or use --flatpak."


def run_signal_cli(account, command_args, launcher, soft=False):
    """Run a signal-cli command and return parsed JSON.

    With soft=True, failures return None (and warn) instead of exiting, for
    optional calls like listContacts.
    """
    cmd = launcher + ["-a", account, "--output=json"] + command_args
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        if soft:
            return None
        sys.exit(f"Could not run '{launcher[0]}'. {_launch_hint(launcher)}")
    if proc.returncode != 0:
        if soft:
            sys.stderr.write(f"warning: signal-cli {' '.join(command_args)} failed; "
                             f"continuing without it.\n")
            return None
        sys.exit(f"signal-cli failed ({' '.join(command_args)}):\n{proc.stderr.strip()}")
    out = proc.stdout.strip()
    if not out:
        return []
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        if soft:
            return None
        sys.exit(f"Could not parse signal-cli JSON for: {' '.join(command_args)}\n"
                 f"First 400 chars:\n{out[:400]}")


def signal_cli_receive(account, launcher, timeout=10):
    cmd = launcher + ["-a", account, "receive", "-t", str(timeout)]
    try:
        subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit(f"Could not run '{launcher[0]}'. {_launch_hint(launcher)}")


# ---------- normalization (tolerant to field-name drift across versions) ----------

def normalize_identities(raw):
    out = []
    for item in raw:
        out.append({
            "number": _first(item, "number"),
            "uuid": _first(item, "uuid", "serviceId", "aci"),
            "safety_number": _first(item, "safetyNumber", "safety_number", "safetynumber"),
        })
    return out


def normalize_member(m):
    if isinstance(m, str):
        if re.fullmatch(r"\+?\d+", m):
            return {"number": m, "uuid": None}
        return {"number": None, "uuid": m}
    if isinstance(m, dict):
        return {"number": _first(m, "number"),
                "uuid": _first(m, "uuid", "serviceId", "aci")}
    return {"number": None, "uuid": None}


def normalize_groups(raw):
    groups = []
    for g in raw:
        members = [normalize_member(m) for m in (_first(g, "members", default=[]) or [])]
        groups.append({
            "id": _first(g, "id", "groupId"),
            "name": _first(g, "name", default="(unnamed group)"),
            "members": members,
        })
    return groups


# ---------- name resolution (so a match shows a human-recognizable label) ----------

def normalize_contacts(raw):
    """From listContacts JSON, pull number/uuid/username/profile name per account."""
    out = []
    for item in raw or []:
        profile = item.get("profile") or {}
        given = _first(profile, "givenName", "given_name", default="")
        family = _first(profile, "familyName", "lastName", "family_name", default="")
        profile_name = " ".join(p for p in (given, family) if p).strip()
        out.append({
            "number": _first(item, "number"),
            "uuid": _first(item, "uuid", "serviceId", "aci"),
            "username": _first(item, "username", default=""),
            "contact_name": _first(item, "name", "nickname", default=""),
            "profile_name": profile_name,
        })
    return out


def build_name_map(contacts):
    m = {}
    for c in contacts:
        if c["uuid"]:
            m[c["uuid"]] = c
        if c["number"]:
            m.setdefault(c["number"], c)
    return m


def describe_member(member, name_map):
    """Resolve a member's ACI to a human label plus all known locators."""
    aci = member.get("uuid") or ""
    number = member.get("number") or ""
    info = name_map.get(aci) or name_map.get(number) or {}
    profile_name = info.get("profile_name", "")
    contact_name = info.get("contact_name", "")
    username = info.get("username", "")
    number = number or info.get("number", "") or ""
    display_name = profile_name or contact_name or "(no profile name received -- run --receive)"
    return {
        "aci": aci,
        "number": number,
        "username": username,
        "profile_name": profile_name,
        "contact_name": contact_name,
        "display_name": display_name,
    }


def removal_command(launcher, account, group_id, recipient, ban=False):
    parts = launcher + ["-a", account, "updateGroup", "-g", group_id,
                        "--remove-member", recipient]
    if ban:
        parts += ["--ban", recipient]
    return " ".join(shlex.quote(p) for p in parts)


def remove_member(launcher, account, group_id, recipient, ban=False):
    """Remove (and optionally ban) a member. Returns (ok, message)."""
    cmd = launcher + ["-a", account, "updateGroup", "-g", group_id,
                      "--remove-member", recipient]
    if ban:
        cmd += ["--ban", recipient]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        return False, f"could not run '{launcher[0]}'"
    if proc.returncode == 0:
        return True, (proc.stdout.strip() or "ok")
    return False, (proc.stderr.strip() or proc.stdout.strip() or "unknown error")


# ---------- core logic ----------

def detect_my_half(identities, override=None):
    if override:
        h = digits_only(override)
        if len(h) != 30:
            sys.exit("--my-half must be exactly 30 digits after removing spaces.")
        return h, "(provided via --my-half)"

    counter = Counter()
    n_valid = 0
    for idn in identities:
        halves = split_halves(idn["safety_number"])
        if not halves:
            continue
        n_valid += 1
        counter[halves[0]] += 1
        counter[halves[1]] += 1

    if n_valid < 2:
        sys.exit("Need at least 2 identities with valid safety numbers to auto-detect "
                 "your half.\nFind it manually (the 30-digit block common to two of your "
                 "safety numbers) and pass it with --my-half.")

    my_half, count = counter.most_common(1)[0]
    note = f"appears in {count} of your {n_valid} safety numbers"
    if count < n_valid:
        note += "  [WARNING: not in all of them -- detection may be off; consider --my-half]"
    return my_half, note


def their_half(safety_number, my_half):
    halves = split_halves(safety_number)
    if not halves:
        return None
    a, b = halves
    if a == my_half:
        return b
    if b == my_half:
        return a
    return None  # my half not found in this number -> can't isolate theirs


def load_watchlist(path):
    halves, problems = {}, []
    try:
        f = open(path, encoding="utf-8")
    except OSError as e:
        sys.exit(f"Could not open watchlist '{path}': {e}")
    with f:
        for lineno, line in enumerate(f, 1):
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            d = digits_only(raw)
            if len(d) == 30:
                halves[d] = raw
            elif len(d) == 60:
                problems.append((lineno, raw, "60 digits -- that's a FULL safety number, "
                                              "not a half. Skipped."))
            else:
                problems.append((lineno, raw, f"{len(d)} digits (expected 30). Skipped."))
    return halves, problems


# ---------- reporting ----------

def main():
    ap = argparse.ArgumentParser(description="Match signal-cli group members against a "
                                             "watchlist of safety-number halves.")
    ap.add_argument("watchlist", help="file with one 30-digit safety-number half per line")
    ap.add_argument("-a", "--account", help="your signal-cli account, e.g. +15551234567")
    ap.add_argument("--signal-cli", default="signal-cli", help="path to signal-cli binary")
    ap.add_argument("--flatpak", action="store_true",
                    help="invoke signal-cli via 'flatpak run' instead of a host binary")
    ap.add_argument("--flatpak-app", default="org.asamk.SignalCli",
                    help="flatpak application id (used with --flatpak)")
    ap.add_argument("--my-half", help="override auto-detection of your own 30-digit half")
    ap.add_argument("--identities-json", help="read listIdentities JSON from a file instead")
    ap.add_argument("--groups-json", help="read listGroups -d JSON from a file instead")
    ap.add_argument("--contacts-json",
                    help="read listContacts JSON from a file (for name resolution in file mode)")
    ap.add_argument("--receive", action="store_true",
                    help="run 'signal-cli receive' first to refresh identities and profiles")
    ap.add_argument("--remove", action="store_true",
                    help="offer to remove each matched member from its group "
                         "(linked account must be a group admin)")
    ap.add_argument("--ban", action="store_true",
                    help="with --remove, also ban the member from rejoining via link")
    ap.add_argument("--yes", action="store_true",
                    help="with --remove, skip the per-member confirmation prompt (DANGEROUS)")
    ap.add_argument("--report-json", help="also write a machine-readable report to this path")
    args = ap.parse_args()

    using_cli = not (args.identities_json and args.groups_json)
    if using_cli and not args.account:
        sys.exit("Provide -a/--account (or supply both --identities-json and --groups-json).")

    launcher = build_launcher(args)

    if args.receive and using_cli:
        signal_cli_receive(args.account, launcher)

    # identities
    if args.identities_json:
        raw_idn = json.load(open(args.identities_json, encoding="utf-8"))
    else:
        raw_idn = run_signal_cli(args.account, ["listIdentities"], launcher)
    identities = normalize_identities(raw_idn)

    # groups
    if args.groups_json:
        raw_grp = json.load(open(args.groups_json, encoding="utf-8"))
    else:
        raw_grp = run_signal_cli(args.account, ["listGroups", "-d"], launcher)
    groups = normalize_groups(raw_grp)

    # contacts -> name map (optional; failure is non-fatal)
    if args.contacts_json:
        raw_contacts = json.load(open(args.contacts_json, encoding="utf-8"))
    elif using_cli:
        raw_contacts = run_signal_cli(args.account, ["listContacts"], launcher, soft=True) or []
    else:
        raw_contacts = []
    name_map = build_name_map(normalize_contacts(raw_contacts))

    watchlist, problems = load_watchlist(args.watchlist)
    if not watchlist:
        sys.exit("Watchlist contained no usable 30-digit halves.")

    my_half, my_note = detect_my_half(identities, args.my_half)

    # lookup tables: identifier -> safety number
    by_uuid, by_number = {}, {}
    for idn in identities:
        if idn["uuid"]:
            by_uuid[idn["uuid"]] = idn["safety_number"]
        if idn["number"]:
            by_number[idn["number"]] = idn["safety_number"]

    hits = defaultdict(list)     # matched half -> [ {group, group_id, member} ]
    unresolved = []              # (group, member_id) with no known identity
    anomalies = []               # (group, member_id) where our half wasn't present
    total_members = resolved = 0

    for g in groups:
        for m in g["members"]:
            total_members += 1
            mid = m["uuid"] or m["number"] or "(unknown)"
            sn = None
            if m["uuid"] and m["uuid"] in by_uuid:
                sn = by_uuid[m["uuid"]]
            elif m["number"] and m["number"] in by_number:
                sn = by_number[m["number"]]
            if not sn:
                unresolved.append((g["name"], mid))
                continue
            resolved += 1
            th = their_half(sn, my_half)
            if th is None:
                anomalies.append((g["name"], mid))
                continue
            if th in watchlist:
                hits[th].append({"group": g["name"], "group_id": g.get("id"), "member": m})

    # Build enriched match records once, reused for console + removal + JSON.
    match_records = []
    for half, locations in hits.items():
        recs = []
        for loc in locations:
            d = describe_member(loc["member"], name_map)
            recipient = d["aci"] or d["number"]
            cmd = (removal_command(launcher, args.account, loc["group_id"], recipient, args.ban)
                   if (args.account and loc["group_id"] and recipient) else None)
            recs.append({"group": loc["group"], "group_id": loc["group_id"],
                         "remove_command": cmd, **d})
        match_records.append({"half": watchlist[half], "locations": recs})


    # ---- print report ----
    line = "=" * 72
    print(line)
    print("SIGNAL INFILTRATOR CHECK")
    print(line)
    print(f"Your half (subtracted out): {my_half}")
    print(f"  -> {my_note}")
    print(f"Watchlist halves loaded: {len(watchlist)}")
    print(f"Groups scanned: {len(groups)}")
    print(f"Members: {total_members} total, {resolved} with a known identity key, "
          f"{len(unresolved)} unresolved.")
    print(line)

    if match_records:
        total_hits = sum(len(r["locations"]) for r in match_records)
        print(f"\n*** {total_hits} MATCH(ES) ACROSS "
              f"{len(match_records)} WATCHLIST ENTRY/ENTRIES ***\n")
        for rec in match_records:
            print(f"[MATCH] watchlist half {rec['half']}")
            for loc in rec["locations"]:
                extras = ""
                if loc["username"]:
                    extras += f"   username: {loc['username']}"
                if loc["number"]:
                    extras += f"   number: {loc['number']}"
                print(f"        group : {loc['group']!r}")
                print(f"        member: {loc['display_name']}{extras}")
                print(f"        aci   : {loc['aci']}   (rename-proof id; ground truth)")
                if loc["remove_command"]:
                    print(f"        remove: {loc['remove_command']}")
            print()
    else:
        print("\nNo watchlist halves matched any resolvable group member.")
        print("(Remember: this is weak evidence of absence -- see caveats.)\n")

    unmatched = [watchlist[h] for h in watchlist if h not in hits]
    if unmatched:
        print(f"Watchlist entries with no match ({len(unmatched)}):")
        for disp in unmatched:
            print(f"  - {disp}")
        print()

    if unresolved:
        print(f"Members with NO known identity key ({len(unresolved)}) "
              f"-- blind spots, not cleared:")
        for gname, mid in unresolved[:40]:
            print(f"  - {gname!r}: {mid}")
        if len(unresolved) > 40:
            print(f"  ... and {len(unresolved) - 40} more")
        print("  (Run with --receive, or `signal-cli receive`, then re-run.)\n")

    if anomalies:
        print(f"Anomalies ({len(anomalies)}): your half was not present in these members' "
              f"safety numbers -- possible --my-half mis-detection:")
        for gname, mid in anomalies[:20]:
            print(f"  - {gname!r}: {mid}")
        print()

    if problems:
        print(f"Watchlist lines skipped ({len(problems)}):")
        for lineno, raw, why in problems:
            print(f"  - line {lineno}: {why}")
        print()

    print(line)
    print("Reminder: a match = same identity KEY as the flagged account, not proof of "
          "intent.\nKeys rotate on reinstall/re-registration, so refresh the watchlist if "
          "time has passed.")
    print(line)

    # ---- optional removal ----
    removals = []
    if args.remove and match_records:
        print()
        print(line)
        print("REMOVAL  (the linked account must be an ADMIN of each group)")
        print("A match confirms the identity KEY, not intent -- verify before removing.")
        print(line)
        if not args.account:
            print("Cannot remove in file-input mode (no -a/--account). "
                  "Use the printed 'remove:' commands manually.")
        elif not args.yes and not sys.stdin.isatty():
            print("Refusing to remove non-interactively without --yes. Re-run with --yes "
                  "to confirm, or use the printed 'remove:' commands manually.")
        else:
            removed = failed = skipped = 0
            for rec in match_records:
                for loc in rec["locations"]:
                    recipient = loc["aci"] or loc["number"]
                    target = f"{loc['display_name']} (aci {loc['aci']}) from {loc['group']!r}"
                    if not loc["group_id"] or not recipient:
                        print(f"  cannot remove (missing group id or recipient): {target}")
                        failed += 1
                        continue
                    if not args.yes:
                        try:
                            ans = input(f"Remove {target}? [y/N] ").strip().lower()
                        except EOFError:
                            ans = "n"
                        if ans not in ("y", "yes"):
                            print("  skipped.")
                            skipped += 1
                            continue
                    ok, msg = remove_member(launcher, args.account, loc["group_id"],
                                            recipient, args.ban)
                    status = "removed" + (" + banned" if args.ban else "")
                    removals.append({"target": target, "ok": ok, "message": msg,
                                     "banned": bool(args.ban)})
                    if ok:
                        print(f"  {status}: {target}")
                        removed += 1
                    else:
                        print(f"  FAILED: {target}\n    {msg}")
                        failed += 1
            print(f"\nRemoval summary: {removed} removed, {failed} failed, {skipped} skipped.")
        print(line)

    if args.report_json:
        report = {
            "my_half": my_half,
            "my_half_note": my_note,
            "watchlist_count": len(watchlist),
            "groups_scanned": len(groups),
            "members_total": total_members,
            "members_resolved": resolved,
            "matches": match_records,
            "watchlist_unmatched": unmatched,
            "unresolved_members": [{"group": g, "member": m} for g, m in unresolved],
            "anomalies": [{"group": g, "member": m} for g, m in anomalies],
            "skipped_watchlist_lines": [{"line": ln, "reason": why} for ln, _, why in problems],
            "removals": removals,
        }
        with open(args.report_json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\nMachine-readable report written to {args.report_json}")

    # exit non-zero if anything matched, so it's pipeline-friendly
    sys.exit(1 if match_records else 0)


if __name__ == "__main__":
    main()
