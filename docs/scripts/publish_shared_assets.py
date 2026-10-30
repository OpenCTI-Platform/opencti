"""Add the shared images of the last docs build to the gh-pages branch, then push it.

`mkdocs build` / `mike deploy` collect the images used by the pages in
site-shared/shared-assets/, named after their content hash (see hooks/shared_assets.py).
This script adds the ones not published yet to /shared-assets/ at the root of the
local gh-pages branch, on top of the version mike just committed, and pushes the
branch: the version and its images go live together.

Images are only added: a given name always holds the same content, and published
versions keep using the images they reference.

Usage (from the docs/ directory):
    mike deploy [--update-aliases] <version> [alias]   # without --push
    python scripts/publish_shared_assets.py --push

Without --push, only lists the images that would be added.
Options:
    --remote <name>   remote to push to (default: origin)
    --branch <name>   pages branch (default: gh-pages)
"""

import argparse
import os
import subprocess
import sys
import tempfile

STAGING_DIR = os.path.join("site-shared", "shared-assets")
PUBLISHED_DIR = "shared-assets"


def git(*args, cwd, env=None, stdin=None):
    # Bytes, not text mode: on Windows, text mode would turn "\n" into "\r\n" in the paths sent on stdin
    result = subprocess.run(["git", *args], cwd=cwd, env=env, input=stdin.encode("utf-8") if stdin else None, capture_output=True)
    if result.returncode != 0:
        sys.exit(f"[ERROR] git {args[0]} failed: {result.stderr.decode('utf-8', 'replace').strip()}")
    return result.stdout.decode("utf-8").strip()


def main():
    parser = argparse.ArgumentParser(description="Publish the shared docs images and push the pages branch.")
    parser.add_argument("--push", action="store_true", help="commit and push (default: list what would be added)")
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--branch", default="gh-pages")
    args = parser.parse_args()

    docs_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    staging = os.path.join(docs_root, STAGING_DIR)
    if not os.path.isdir(staging):
        sys.exit(f"[ERROR] {staging} not found: build the docs first (mkdocs build or mike deploy)")

    # Run git from the repository root: tree paths are relative to the root of the pages branch
    repo_root = git("rev-parse", "--show-toplevel", cwd=docs_root)
    base = subprocess.run(["git", "rev-parse", "--verify", "--quiet", f"refs/heads/{args.branch}"],
                          cwd=repo_root, capture_output=True, text=True).stdout.strip()
    if not base:
        sys.exit(f"[ERROR] local branch {args.branch} not found: deploy the version with mike first")

    published = set(git("ls-tree", "--name-only", f"{base}:{PUBLISHED_DIR}", cwd=repo_root).splitlines()) \
        if subprocess.run(["git", "cat-file", "-e", f"{base}:{PUBLISHED_DIR}"], cwd=repo_root, capture_output=True).returncode == 0 \
        else set()
    new_images = sorted(name for name in os.listdir(staging) if name not in published)
    print(f"{len(new_images)} new image(s) to publish, {len(os.listdir(staging)) - len(new_images)} already published")
    for name in new_images:
        print(f"  {name}")
    if not args.push:
        print("Dry run: nothing committed or pushed. Use --push to publish.")
        return

    if new_images:
        blobs = git("hash-object", "-w", "--stdin-paths", cwd=repo_root,
                    stdin="\n".join(os.path.join(staging, name) for name in new_images)).splitlines()
        # Build the new tree in a temporary index, on top of the version mike just committed
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, GIT_INDEX_FILE=os.path.join(tmp, "index"))
            git("read-tree", base, cwd=repo_root, env=env)
            git("update-index", "--add", "--index-info", cwd=repo_root, env=env,
                stdin="".join(f"100644 {blob}\t{PUBLISHED_DIR}/{name}\n" for name, blob in zip(new_images, blobs)))
            tree = git("write-tree", cwd=repo_root, env=env)
        commit = git("commit-tree", tree, "-p", base, "-m", f"Publish {len(new_images)} shared docs image(s)", cwd=repo_root)
        git("update-ref", f"refs/heads/{args.branch}", commit, base, cwd=repo_root)
        print(f"Committed {commit[:7]} on {args.branch}")

    # Fast-forward only: fails instead of overwriting if the remote branch moved in the meantime
    git("push", "--quiet", args.remote, f"refs/heads/{args.branch}:refs/heads/{args.branch}", cwd=repo_root)
    print(f"Pushed {args.branch} to {args.remote}")


if __name__ == "__main__":
    main()
