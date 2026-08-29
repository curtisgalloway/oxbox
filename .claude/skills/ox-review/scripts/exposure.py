#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Decide whether the project in front of you is already published.

`ox` sends source code to a venue whose listing is an evaluation deal:
prompts and completions are logged and shared with whoever owns the model,
and on OpenRouter the free cloaked listings only work with prompt logging
switched *on*. Sending code that anyone can already `git clone` costs
nothing new. Sending code that nobody outside the company can read
publishes it to an unnamed third party, and no later deletion unpublishes
it.

That is the whole question this script answers, and it answers it the
direct way: can an anonymous stranger fetch this repository right now?
Not "does the URL look like github.com" — a hostname is a guess, and the
enterprise install at github.example.com looks exactly like the public
one. The probe is a real unauthenticated request, carrying no credential
of any kind, so a 200 means the code is genuinely readable by the world
and a 404 means it is not (or that the repo was renamed, which is the same
answer for our purposes: do not assume).

Verdicts: public | not-public | unknown | no-remote | not-a-repo.
Exit 0 for `public`, 10 for everything else, because "the check could not
reach the network" and "the repo is private" call for the same pause.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 15
USER_AGENT = "oxbox ox-review exposure probe (+https://github.com/curtisgalloway/oxbox)"

# Hosts whose API answers "is this repository public" precisely, including a
# license and a fork flag the operator may want to weigh. Anything not listed
# — a self-hosted Forgejo, an enterprise GitHub, a bare git over https — still
# gets the anonymous-clone probe below, which is the check that actually
# decides. This table only buys better reporting, never a laxer verdict.
PROVIDER_APIS = {
    "github.com": "https://api.github.com/repos/{owner}/{name}",
    "gitlab.com": "https://gitlab.com/api/v4/projects/{owner_name_encoded}?license=true",
    "codeberg.org": "https://codeberg.org/api/v1/repos/{owner}/{name}",
    "bitbucket.org": "https://api.bitbucket.org/2.0/repositories/{owner}/{name}",
    "gitea.com": "https://gitea.com/api/v1/repos/{owner}/{name}",
}


def git(args, cwd):
    """Run git and return stripped stdout, or None if the command failed."""
    try:
        done = subprocess.run(["git"] + args, cwd=cwd, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    return done.stdout.decode("utf-8", "replace").strip()


def parse_remote(url):
    """Split a remote URL into (host, owner, name), or None if it isn't one.

    Handles the three shapes git accepts for a hosted repo: https URLs,
    scp-style `git@host:owner/name`, and ssh:// URLs. A local path or a
    file:// remote is not a publication channel, so it returns None and the
    caller treats the project as unpublished.
    """
    if not url:
        return None
    url = url.strip()
    scp = re.match(r"^(?:[^@/]+@)?([A-Za-z0-9._-]+\.[A-Za-z0-9._-]+):(?!/)(.+)$", url)
    if scp and "://" not in url:
        host, path = scp.group(1), scp.group(2)
    else:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("https", "http", "ssh", "git"):
            return None
        host = (parts.hostname or "").lower()
        path = parts.path
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if not host or "/" not in path:
        return None
    owner, _, name = path.rpartition("/")
    if not owner or not name:
        return None
    return host.lower(), owner, name


def fetch(url, accept="application/json"):
    """Unauthenticated GET. Returns (status, content_type, body_bytes).

    No Authorization header, no netrc, no token from the environment: the
    point of the probe is to learn what a stranger sees, and a request that
    quietly used the operator's credentials would report every private repo
    as public. urllib sends nothing it is not given, and nothing is given.
    """
    request = urllib.request.Request(url, headers={
        "Accept": accept,
        "User-Agent": USER_AGENT,
    })
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.status, response.headers.get("Content-Type", ""), response.read(200000)
    except urllib.error.HTTPError as error:
        return error.code, error.headers.get("Content-Type", "") if error.headers else "", b""
    except Exception as error:  # network down, TLS failure, proxy refusal, DNS
        return None, str(error), b""


def probe_anonymous_clone(host, owner, name):
    """Ask the git smart-HTTP endpoint whether an anonymous clone is allowed.

    This is the provider-agnostic answer. Every git host that serves https
    exposes /info/refs?service=git-upload-pack, and it is the exact request
    `git clone` makes first. A ref advertisement means the world can read
    the code; a 401/403/404 means it cannot.
    """
    url = "https://%s/%s/%s/info/refs?service=git-upload-pack" % (host, owner, name)
    status, content_type, body = fetch(url, accept="*/*")
    if status is None:
        return {"ok": None, "detail": "probe failed: %s" % content_type, "url": url}
    advertised = ("git-upload-pack-advertisement" in (content_type or "")
                  or body.startswith(b"001e# service=git-upload-pack"))
    if status == 200 and advertised:
        return {"ok": True, "detail": "anonymous clone allowed (HTTP 200)", "url": url}
    if status == 200:
        # A login page or an html error rendered with a 200. Not proof of
        # anything, so it must not read as proof of publicity.
        return {"ok": None,
                "detail": "HTTP 200 but no git ref advertisement (content-type %r)" % content_type,
                "url": url}
    return {"ok": False, "detail": "HTTP %s" % status, "url": url}


def probe_provider_api(host, owner, name):
    """Read visibility, license and fork status from a known host's API."""
    template = PROVIDER_APIS.get(host)
    if not template:
        return None
    url = template.format(
        owner=urllib.parse.quote(owner, safe=""),
        name=urllib.parse.quote(name, safe=""),
        owner_name_encoded=urllib.parse.quote("%s/%s" % (owner, name), safe=""),
    )
    status, _, body = fetch(url)
    if status is None or status != 200 or not body:
        return {"reachable": False, "status": status, "url": url}
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return {"reachable": False, "status": status, "url": url}
    private = data.get("private")
    if private is None:
        private = data.get("is_private")
    if private is None and data.get("visibility") is not None:
        private = data.get("visibility") != "public"
    licence = data.get("license")
    if isinstance(licence, dict):
        licence = (licence.get("spdx_id") or licence.get("nickname")
                   or licence.get("name") or licence.get("key"))
    if licence is None:
        licence = data.get("license_url") or data.get("spdx_id")
    return {
        "reachable": True,
        "url": url,
        "private": private,
        "visibility": data.get("visibility"),
        "license": licence,
        "fork": data.get("fork") or data.get("forked_from_project") is not None
                or bool(data.get("parent")),
        "archived": data.get("archived"),
    }


def assess_remote(name, url):
    """Probe one remote and reduce the evidence to a verdict."""
    result = {"remote": name, "url": url, "host": None, "owner": None,
              "repo": None, "verdict": "unknown", "notes": [],
              "api": None, "clone_probe": None}
    parsed = parse_remote(url)
    if parsed is None:
        result["verdict"] = "not-public"
        result["notes"].append(
            "remote %r is not a hosted https/ssh repository, so nothing here is published" % url)
        return result
    host, owner, repo = parsed
    result.update({"host": host, "owner": owner, "repo": repo})

    api = probe_provider_api(host, owner, repo)
    result["api"] = api
    clone = probe_anonymous_clone(host, owner, repo)
    result["clone_probe"] = clone

    if api and api.get("reachable") and api.get("private") is not None:
        result["verdict"] = "not-public" if api["private"] else "public"
        if api.get("license") in (None, "", "NOASSERTION"):
            # Public and open source are not the same claim. All-rights-reserved
            # source on a public host is still readable by the world, so the
            # disclosure question is settled — but the operator may care, and
            # a gate that silently conflates the two is lying by omission.
            result["notes"].append(
                "no license detected: the code is publicly readable but not "
                "necessarily open source")
        if api.get("archived"):
            result["notes"].append("repository is archived")
    elif clone["ok"] is True:
        result["verdict"] = "public"
        result["notes"].append(
            "provider API unavailable; verdict rests on the anonymous clone probe")
    elif clone["ok"] is False:
        result["verdict"] = "not-public"
    else:
        result["verdict"] = "unknown"
        result["notes"].append(
            "could not reach %s to check: %s" % (host, clone["detail"]))

    # Cross-check the two probes. They should agree; when they don't, the
    # discrepancy is the finding, and the safer reading wins.
    if result["verdict"] == "public" and clone["ok"] is False:
        result["verdict"] = "unknown"
        result["notes"].append(
            "the API calls this repository public but an anonymous clone was "
            "refused (%s) — treat as unresolved" % clone["detail"])
    return result


def local_publication_gap(root):
    """Note how much of the working tree has never left this machine.

    Reviewing unpushed work is the normal case — you want the findings
    *before* you push — so this is context for the human, never a gate.
    """
    notes = []
    dirty = git(["status", "--porcelain"], root)
    if dirty:
        notes.append("%d file(s) modified or untracked in the working tree"
                     % len(dirty.splitlines()))
    upstream = git(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"], root)
    if upstream is None:
        branch = git(["rev-parse", "--abbrev-ref", "HEAD"], root) or "HEAD"
        notes.append("branch %s has no upstream — its commits are not on any remote" % branch)
    else:
        ahead = git(["rev-list", "--count", "%s..HEAD" % upstream], root)
        if ahead and ahead != "0":
            notes.append("%s commit(s) ahead of %s and not yet pushed" % (ahead, upstream))
    return notes


def main():
    global TIMEOUT
    parser = argparse.ArgumentParser(
        description="Check whether the project under review is publicly readable.")
    parser.add_argument("--path", default=".", help="directory inside the project (default: .)")
    parser.add_argument("--json", action="store_true", help="print the machine-readable record only")
    parser.add_argument("--timeout", type=int, default=TIMEOUT, help="per-probe timeout in seconds")
    args = parser.parse_args()
    TIMEOUT = args.timeout

    report = {"path": os.path.abspath(args.path), "verdict": "unknown",
              "root": None, "primary": None, "remotes": [], "local": []}

    root = git(["rev-parse", "--show-toplevel"], args.path)
    if not root:
        report["verdict"] = "not-a-repo"
        report["summary"] = ("%s is not a git repository, so there is no remote to "
                             "check and nothing here is known to be published"
                             % report["path"])
        emit(report, args.json)
        return 10
    report["root"] = root

    listing = git(["remote"], root)
    remotes = [line for line in (listing or "").splitlines() if line.strip()]
    if not remotes:
        report["verdict"] = "no-remote"
        report["summary"] = ("%s has no git remote: this code exists only on this "
                             "machine and sending it would be its first publication" % root)
        report["local"] = local_publication_gap(root)
        emit(report, args.json)
        return 10

    primary_name = "origin" if "origin" in remotes else remotes[0]
    for name in remotes:
        url = git(["remote", "get-url", name], root) or ""
        report["remotes"].append(assess_remote(name, url))

    primary = next(r for r in report["remotes"] if r["remote"] == primary_name)
    report["primary"] = primary_name
    report["verdict"] = primary["verdict"]
    for other in report["remotes"]:
        if other["remote"] != primary_name and other["verdict"] != "public":
            primary["notes"].append(
                "remote %r (%s) is %s — if your work lives there, this project "
                "is not published" % (other["remote"], other["url"], other["verdict"]))
    report["local"] = local_publication_gap(root)
    report["summary"] = summarize(primary)
    emit(report, args.json)
    return 0 if report["verdict"] == "public" else 10


def summarize(primary):
    where = "%s/%s on %s" % (primary["owner"], primary["repo"], primary["host"]) \
        if primary["host"] else primary["url"]
    if primary["verdict"] == "public":
        return "%s is publicly readable: anyone can already clone this code" % where
    if primary["verdict"] == "not-public":
        return ("%s is NOT publicly readable — sending it to a model venue would "
                "publish it to an unnamed third party" % where)
    return ("could not establish whether %s is publicly readable; treat it as "
            "private until you know otherwise" % where)


def emit(report, as_json):
    if as_json:
        print(json.dumps(report, indent=2))
        return
    print("verdict: %s" % report["verdict"])
    print(report["summary"])
    for remote in report["remotes"]:
        print("\nremote %s -> %s" % (remote["remote"], remote["url"]))
        print("  verdict: %s" % remote["verdict"])
        api = remote.get("api")
        if api and api.get("reachable"):
            print("  api: private=%s visibility=%s license=%s fork=%s"
                  % (api.get("private"), api.get("visibility"),
                     api.get("license"), api.get("fork")))
        clone = remote.get("clone_probe")
        if clone:
            print("  anonymous clone: %s" % clone["detail"])
        for note in remote["notes"]:
            print("  note: %s" % note)
    if report["local"]:
        print("\nnot yet on any remote (normal for pre-push review, not a blocker):")
        for note in report["local"]:
            print("  - %s" % note)
    print("\n%s" % ("gate: clear" if report["verdict"] == "public"
                    else "gate: CONFIRMATION REQUIRED before sending anything"))


if __name__ == "__main__":
    sys.exit(main())
