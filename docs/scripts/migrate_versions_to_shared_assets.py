"""Move the images of already published docs versions to the shared assets.

Since hooks/shared_assets.py, new docs builds reference their images from
/shared-assets/<name>-<content hash>.<ext> at the gh-pages root instead of copying
them into every version. This one-off script applies the same layout to the versions
published before: it works directly on the files of the gh-pages branch (no rebuild),
and for each version:

* names each image after its content hash, like the hook, so an image identical in
  several versions (or in new builds) is stored once in shared-assets/
* rewrites the image links of the version's HTML pages to /shared-assets/...
* removes the version's own copy of the images it no longer references

An image still referenced in another way (e.g. by an absolute link or from CSS) is
kept in the version. Existing files are reused as-is: only rewritten pages are new
content. Everything goes into a single commit on the pages branch.

Usage (from the docs/ directory, with an up-to-date local gh-pages branch):
    python scripts/migrate_versions_to_shared_assets.py             # dry run: report only
    python scripts/migrate_versions_to_shared_assets.py --commit    # commit on the local branch
    python scripts/migrate_versions_to_shared_assets.py --push      # commit and push
Options:
    --versions <v1,v2,...>   only migrate these versions (default: all of versions.json)
    --remote <name>          remote to compare with and push to (default: origin)
    --branch <name>          pages branch (default: gh-pages)
"""

import argparse
import hashlib
import json
import os
import posixpath
import re
import subprocess
import sys
import tempfile
from urllib.parse import quote, unquote

IMAGE_EXTENSIONS = {".png", ".gif", ".jpg", ".jpeg", ".svg", ".webp"}
SHARED_DIR = "shared-assets"
# Same rewrite and safety-net patterns as hooks/shared_assets.py
ATTRIBUTE_RE = re.compile(r'\b(src|href)="([^"]+)"')
LINK_RE = re.compile(r'\b(?:src|href|srcset|poster|data-[\w-]+)=["\']([^"\']+)["\']|url\(([^)]+)\)')


def git(*args, cwd, env=None, stdin=None):
    # Bytes, not text mode: on Windows, text mode would turn "\n" into "\r\n" on stdin
    result = subprocess.run(["git", *args], cwd=cwd, env=env, input=stdin, capture_output=True)
    if result.returncode != 0:
        sys.exit(f"[ERROR] git {args[0]} failed: {result.stderr.decode('utf-8', 'replace').strip()}")
    return result.stdout


class BlobReader:
    """Reads blob contents through a single `git cat-file --batch` process."""

    def __init__(self, cwd):
        self.process = subprocess.Popen(["git", "cat-file", "--batch"], cwd=cwd,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def read(self, blob):
        self.process.stdin.write(blob.encode() + b"\n")
        self.process.stdin.flush()
        header = self.process.stdout.readline().split()
        content = self.process.stdout.read(int(header[2]))
        self.process.stdout.read(1)  # trailing newline
        return content

    def close(self):
        self.process.stdin.close()
        self.process.wait()


def write_blobs(contents, marks_file, cwd):
    """Store contents as git blobs in a single pack and return their ids, in order.

    `git fast-import` writes one pack instead of one loose object per blob, which is
    much faster for thousands of pages (especially on Windows).
    """
    process = subprocess.Popen(["git", "fast-import", "--quiet", "--done", f"--export-marks={marks_file}"],
                               cwd=cwd, stdin=subprocess.PIPE)
    for mark, content in enumerate(contents, start=1):
        process.stdin.write(b"blob\nmark :%d\ndata %d\n" % (mark, len(content)))
        process.stdin.write(content + b"\n")
    process.stdin.write(b"done\n")
    process.stdin.close()
    if process.wait() != 0:
        sys.exit("[ERROR] git fast-import failed")
    blobs = {}
    with open(marks_file) as f:
        for line in f:
            mark, blob = line.split()
            blobs[int(mark[1:])] = blob
    return [blobs[mark] for mark in range(1, len(contents) + 1)]


def list_tree(commit, cwd):
    """Return {path: (mode, blob, size)} for every file of the commit."""
    entries = {}
    for record in git("ls-tree", "-r", "-l", "-z", commit, cwd=cwd).split(b"\0"):
        if not record:
            continue
        meta, path = record.split(b"\t", 1)
        mode, _, blob, size = meta.decode().split()
        entries[path.decode("utf-8")] = (mode, blob, 0 if size == "-" else int(size))
    return entries


def resolve(page_path, link):
    """Return the tree path a relative link of a page points to, or None."""
    if re.match(r"^([a-z][a-z0-9+.-]*:|/|#)", link):
        return None
    target = unquote(link.split("#")[0].split("?")[0])
    return posixpath.normpath(posixpath.join(posixpath.dirname(page_path), target)) if target else None


def main():
    parser = argparse.ArgumentParser(description="Move the images of published docs versions to the shared assets.")
    parser.add_argument("--commit", action="store_true", help="commit on the local pages branch")
    parser.add_argument("--push", action="store_true", help="commit and push")
    parser.add_argument("--versions", help="comma-separated versions to migrate (default: all)")
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--branch", default="gh-pages")
    args = parser.parse_args()

    docs_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    repo_root = git("rev-parse", "--show-toplevel", cwd=docs_root).decode().strip()
    base = subprocess.run(["git", "rev-parse", "--verify", "--quiet", f"refs/heads/{args.branch}"],
                          cwd=repo_root, capture_output=True, text=True).stdout.strip()
    if not base:
        sys.exit(f"[ERROR] local branch {args.branch} not found")
    if args.push:
        # Only migrate what is actually published
        git("fetch", "--quiet", args.remote, args.branch, cwd=repo_root)
        remote = git("rev-parse", "FETCH_HEAD", cwd=repo_root).decode().strip()
        if remote != base:
            sys.exit(f"[ERROR] local {args.branch} differs from {args.remote}/{args.branch}: update it first")

    tree = list_tree(base, repo_root)
    published = json.loads(git("show", f"{base}:versions.json", cwd=repo_root))
    versions = [v["version"] for v in published]
    if args.versions:
        wanted = args.versions.split(",")
        unknown = set(wanted) - set(versions)
        if unknown:
            sys.exit(f"[ERROR] unknown version(s): {', '.join(sorted(unknown))}")
        versions = [v for v in versions if v in wanted]

    reader = BlobReader(repo_root)
    shared_names = {}  # blob -> shared file name
    new_shared = {}  # shared path -> blob
    removed, rewritten_pages = [], {}  # paths, path -> new content
    report = []
    try:
        for version in versions:
            prefix = version + "/"
            files = {p: e for p, e in tree.items() if p.startswith(prefix) and e[0] != "120000"}
            images = {p: e for p, e in files.items() if os.path.splitext(p)[1].lower() in IMAGE_EXTENSIONS}
            moved = set()
            pages = {}

            for path, (_, blob, _) in files.items():
                if not path.endswith(".html"):
                    continue
                html = reader.read(blob).decode("utf-8", "surrogateescape")

                def rewrite(match):
                    target = resolve(path, match.group(2))
                    if target not in images:
                        return match.group(0)
                    image_blob = images[target][1]
                    if image_blob not in shared_names:
                        stem, ext = os.path.splitext(posixpath.basename(target))
                        digest = hashlib.sha256(reader.read(image_blob)).hexdigest()[:10]
                        shared_names[image_blob] = f"{stem}-{digest}{ext.lower()}"
                    moved.add(target)
                    return f'{match.group(1)}="/{SHARED_DIR}/{quote(shared_names[image_blob])}"'

                new_html = ATTRIBUTE_RE.sub(rewrite, html)
                pages[path] = new_html
                if new_html != html:
                    rewritten_pages[path] = new_html

            # Safety net: keep an image still linked to under its original name
            by_basename = {}
            for image in moved:
                by_basename.setdefault(posixpath.basename(image), []).append(image)
            kept = set()
            sources = list(pages.values()) + [reader.read(e[1]).decode("utf-8", "ignore")
                                              for p, e in files.items() if p.endswith(".css")]
            for content in sources:
                for attribute, css_url in LINK_RE.findall(content):
                    link = (attribute or css_url).strip("'\" ")
                    basename = posixpath.basename(unquote(link.split("#")[0].split("?")[0]))
                    kept.update(by_basename.get(basename, []))

            for image in moved:
                name = shared_names[images[image][1]]
                new_shared.setdefault(f"{SHARED_DIR}/{name}", images[image][1])
                if image not in kept:
                    removed.append(image)
            freed = sum(images[i][2] for i in moved - kept)
            report.append((version, len(moved - kept), len(kept), freed))
    finally:
        reader.close()

    # Shared images already published (by the publish script or a previous run) are reused
    for path in list(new_shared):
        if path in tree:
            if tree[path][1] != new_shared[path]:
                sys.exit(f"[ERROR] {path} already exists with a different content")
            del new_shared[path]

    total_before = sum(e[2] for e in tree.values())
    removed_bytes = sum(tree[p][2] for p in removed)
    sizes = {}
    if new_shared:
        for record in git("cat-file", "--batch-check", cwd=repo_root,
                          stdin="".join(f"{b}\n" for b in set(new_shared.values())).encode()).decode().splitlines():
            blob, _, size = record.split()
            sizes[blob] = int(size)
    shared_bytes = sum(sizes[b] for b in new_shared.values())
    page_delta = sum(len(c.encode("utf-8", "surrogateescape")) - tree[p][2] for p, c in rewritten_pages.items())
    total_after = total_before - removed_bytes + shared_bytes + page_delta

    print(f"{'version':<22} {'moved':>6} {'kept':>5} {'freed MB':>9}")
    for version, moved_count, kept_count, freed in report:
        print(f"{version:<22} {moved_count:>6} {kept_count:>5} {freed / 1024 / 1024:>9.1f}")
    print(f"\n{len(report)} version(s): {len(removed)} image copies removed, {len(new_shared)} new shared image(s), "
          f"{len(rewritten_pages)} page(s) rewritten")
    print(f"{args.branch} size: {total_before / 1024 / 1024:,.0f} MB -> {total_after / 1024 / 1024:,.0f} MB")
    if not (args.commit or args.push):
        print("Dry run: nothing committed. Use --commit (local only) or --push.")
        return
    if not removed and not new_shared and not rewritten_pages:
        print("Nothing to migrate.")
        return

    with tempfile.TemporaryDirectory() as tmp:
        page_blobs = write_blobs([c.encode("utf-8", "surrogateescape") for c in rewritten_pages.values()],
                                 os.path.join(tmp, "marks"), repo_root)

        entries = [f"0 {'0' * 40}\t{p}" for p in removed]
        entries += [f"100644 {blob}\t{p}" for p, blob in new_shared.items()]
        entries += [f"100644 {blob}\t{p}" for p, blob in zip(rewritten_pages, page_blobs)]
        env = dict(os.environ, GIT_INDEX_FILE=os.path.join(tmp, "index"))
        git("read-tree", base, cwd=repo_root, env=env)
        git("update-index", "-z", "--index-info", cwd=repo_root, env=env,
            stdin="".join(e + "\0" for e in entries).encode("utf-8"))
        new_tree = git("write-tree", cwd=repo_root, env=env).decode().strip()

    message = f"Migrate {len(report)} docs version(s) to shared images"
    commit = git("commit-tree", new_tree, "-p", base, "-m", message, cwd=repo_root).decode().strip()
    git("update-ref", f"refs/heads/{args.branch}", commit, base, cwd=repo_root)
    print(f"Committed {commit[:7]} on {args.branch}")
    if args.push:
        # Fast-forward only: fails instead of overwriting if the remote branch moved in the meantime
        git("push", "--quiet", args.remote, f"refs/heads/{args.branch}:refs/heads/{args.branch}", cwd=repo_root)
        print(f"Pushed {args.branch} to {args.remote}")


if __name__ == "__main__":
    main()
