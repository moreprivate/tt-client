#!/usr/bin/env python3

"""
This script intended to fill the local conan cache with the packages required
for building the project. Clean build scenario requires running this script
before running the cmake command. Besides that, it may be also required after
the dependencies updates.

Usage:
    bootstrap_conan_deps.py [nlc_url [dns_libs_url]]

`nlc_url` is the URL of AdGuard's NativeLibsCommon repository
(defaults to https://github.com/AdguardTeam/NativeLibsCommon.git).
`dns_libs_url` is the URL of AdGuard's DnsLibs repository
(defaults to https://github.com/AdguardTeam/DnsLibs.git).
"""

import os
import re
import shutil
import stat
import subprocess
import sys
import time

work_dir = os.path.dirname(os.path.realpath(__file__))
project_dir = os.path.dirname(work_dir)
nlc_url = sys.argv[1] if len(sys.argv) > 1 else 'https://github.com/AdguardTeam/NativeLibsCommon.git'
nlc_dir_name = "native-libs-common"
dns_libs_url = sys.argv[2] if len(sys.argv) > 2 else 'https://github.com/AdguardTeam/DnsLibs.git'
dns_libs_dir_name = "dns-libs"
nlc_versions = []

# Transient network errors (connection reset, early EOF) are common on large
# GitHub clones; retry with backoff rather than failing the whole product build.
GIT_CLONE_ATTEMPTS = int(os.environ.get("TT_GIT_CLONE_ATTEMPTS", "5"))
GIT_CLONE_BACKOFF_SEC = float(os.environ.get("TT_GIT_CLONE_BACKOFF", "3"))


def on_rm_tree_error(func, path, _):
    """
    Workaround for Windows behavior, where `shutil.rmtree`
    fails with an access error (read only file).
    So, attempt to add write permission and try again.
    """
    if not os.access(path, os.W_OK):
        os.chmod(path, stat.S_IWUSR)
        func(path)
    else:
        raise


def remove_dir_if_exists(dir_path):
    """Remove a directory if it exists, handling read-only files on Windows."""
    if os.path.exists(dir_path):
        os.chdir(work_dir)
        shutil.rmtree(dir_path, onerror=on_rm_tree_error)


def revision_for_version(version):
    """
    Map a Conan package version to the git revision to check out.

    Versions are produced by `git describe` and come in two shapes:
      * a plain release tag, e.g. `8.1.39`      -> check out tag `v8.1.39`
      * a snapshot `<tag>-<n>-g<rev>`, e.g.
        `2.8.58-2-g2c375f1c`                     -> check out the commit `<rev>`

    This mirrors how the dns-libs/native_libs_common recipes resolve their
    source revision, so `git describe` in `export_conan.sh` reports exactly the
    requested version.
    """
    described = re.search(r"-g([0-9a-f]+)$", version)
    if described:
        return described.group(1)
    return "v" + version


def is_release_tag_version(version):
    """True when version maps to a plain vX.Y.Z tag (safe for shallow clone)."""
    return not re.search(r"-g([0-9a-f]+)$", version)


def git_clone(url, dest, *, version=None):
    """
    Clone `url` into `dest` with retries. When `version` is a release tag, use a
    shallow single-branch clone of that tag to cut transfer size and flake risk.
    """
    remove_dir_if_exists(dest)
    last_err = None
    for attempt in range(1, GIT_CLONE_ATTEMPTS + 1):
        remove_dir_if_exists(dest)
        cmd = ["git", "clone"]
        if version is not None and is_release_tag_version(version):
            tag = revision_for_version(version)
            cmd += ["--depth", "1", "--branch", tag, "--single-branch"]
        cmd += [url, dest]
        print(f"git clone attempt {attempt}/{GIT_CLONE_ATTEMPTS}: {' '.join(cmd)}",
              flush=True)
        try:
            subprocess.run(cmd, check=True)
            return
        except subprocess.CalledProcessError as err:
            last_err = err
            print(f"git clone failed (attempt {attempt}/{GIT_CLONE_ATTEMPTS}): {err}",
                  flush=True)
            remove_dir_if_exists(dest)
            if attempt < GIT_CLONE_ATTEMPTS:
                time.sleep(GIT_CLONE_BACKOFF_SEC * attempt)
    raise last_err


def export_conan(repo_dir, version):
    """
    Check out the revision matching `version` and export the package to the
    local Conan cache. `export_conan.sh` derives the version from `git describe`
    (it no longer accepts a version argument), so the checked-out revision is
    what determines the exported version.
    """
    rev = revision_for_version(version)
    # Already on the requested ref (typical for a shallow --branch tag clone).
    current = subprocess.run(
        ["git", "-C", repo_dir, "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    want = subprocess.run(
        ["git", "-C", repo_dir, "rev-parse", rev + "^{commit}"],
        capture_output=True, text=True,
    )
    if want.returncode != 0 or want.stdout.strip() != current:
        subprocess.run(["git", "-C", repo_dir, "checkout", rev], check=True)
    subprocess.run([os.path.join(repo_dir, "scripts", "export_conan.sh")],
                   check=True, cwd=repo_dir)


with open(os.path.join(project_dir, "conanfile.py"), "r") as file:
    for line in map(str.strip, file.readlines()):
        if line.startswith('self.requires("native_libs_common/') \
                and ('@adguard/oss"' in line):
            nlc_versions.append(line.split('@')[0].split('/')[1])
        elif line.startswith('self.requires("dns-libs/') \
                and ('@adguard/oss"' in line):
            dns_libs_version = line.split('@')[0].split('/')[1]

dns_libs_dir = os.path.join(work_dir, dns_libs_dir_name)
try:
    git_clone(dns_libs_url, dns_libs_dir, version=dns_libs_version)
    if not is_release_tag_version(dns_libs_version):
        subprocess.run(["git", "-C", dns_libs_dir, "checkout",
                        revision_for_version(dns_libs_version)], check=True)
    os.chdir(dns_libs_dir)
    with open("conanfile.py", "r") as file:
        for line in map(str.strip, file.readlines()):
            if line.startswith('self.requires("native_libs_common/') \
                    and ('@adguard/oss"' in line):
                nlc_versions.append(line.split('@')[0].split('/')[1])

    subprocess.run([os.path.join("scripts", "export_conan.sh")], check=True)
finally:
    remove_dir_if_exists(dns_libs_dir)

os.chdir(work_dir)
nlc_dir = os.path.join(work_dir, nlc_dir_name)
try:
    # Full history for NLC when multiple versions may need checkout; still retry.
    # If only release tags are required, clone the first tag shallow and re-clone
    # per version only when versions differ.
    seen = []
    for v in nlc_versions:
        if v not in seen:
            seen.append(v)

    if len(seen) == 1 and is_release_tag_version(seen[0]):
        git_clone(nlc_url, nlc_dir, version=seen[0])
        export_conan(nlc_dir, seen[0])
    else:
        git_clone(nlc_url, nlc_dir)
        for v in seen:
            export_conan(nlc_dir, v)
finally:
    remove_dir_if_exists(nlc_dir)
