"""Store the images of the documentation once, shared by all docs versions.

During `mkdocs build` (and so `mike deploy`), every image used by a page is renamed
after its content hash (e.g. `audit-3f9a1c2b7e.png`) and referenced from
/shared-assets/ at the site root, instead of being copied into the version folder.
The renamed images are collected in site-shared/shared-assets/, and
scripts/publish_shared_assets.py publishes them to the root of the gh-pages branch.

An unchanged image keeps the same name in every version, so it is stored once.
A changed image gets a new name, and older versions keep using the previous file.

Authors keep adding images next to their pages and linking them relatively;
`mkdocs serve` is left untouched.
"""

import hashlib
import logging
import os
import posixpath
import re
import shutil
from urllib.parse import quote, unquote, urljoin

log = logging.getLogger("mkdocs.hooks.shared_assets")

IMAGE_EXTENSIONS = {".png", ".gif", ".jpg", ".jpeg", ".svg", ".webp"}
URL_PREFIX = "/shared-assets/"
STAGING_DIR = os.path.join("site-shared", "shared-assets")
ATTRIBUTE_RE = re.compile(r'\b(src|href)="([^"]+)"')
# Any link left in the built HTML/CSS: link attributes and CSS url(), not alt texts or titles
LINK_RE = re.compile(r'\b(?:src|href|srcset|poster|data-[\w-]+)=["\']([^"\']+)["\']|url\(([^)]+)\)')

_enabled = True  # on_startup may not run when the build is driven programmatically (e.g. by mike)
_images = {}  # site-relative URL -> File, for every image of the docs
_shared = {}  # site-relative URL -> hashed file name, for images rewritten in pages


def on_startup(command, dirty):
    global _enabled
    _enabled = command != "serve"


def on_files(files, config):
    _images.clear()
    _shared.clear()
    if not _enabled:
        return files
    # Images used by the theme itself (logo, favicon) stay in the version
    theme_images = {config.theme.get("logo"), config.theme.get("favicon")}
    for file in files:
        if os.path.splitext(file.src_uri)[1].lower() in IMAGE_EXTENSIONS and file.src_uri not in theme_images:
            _images[file.url] = file
    return files


def _shared_name(file):
    with open(file.abs_src_path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()[:10]
    stem, ext = os.path.splitext(posixpath.basename(file.src_uri))
    return f"{stem}-{digest}{ext.lower()}"


def on_page_content(html, page, config, files):
    if not _enabled:
        return html

    def rewrite(match):
        value = match.group(2)
        if re.match(r"^([a-z]+:|/|#)", value):
            return match.group(0)
        url = unquote(urljoin("/" + page.url, value).split("#")[0].split("?")[0]).lstrip("/")
        file = _images.get(url)
        if file is None:
            return match.group(0)
        if url not in _shared:
            _shared[url] = _shared_name(file)
        return f'{match.group(1)}="{URL_PREFIX}{quote(_shared[url])}"'

    return ATTRIBUTE_RE.sub(rewrite, html)


def on_post_build(config):
    if not _enabled:
        return
    staging = os.path.join(os.path.dirname(config.config_file_path), STAGING_DIR)
    shutil.rmtree(staging, ignore_errors=True)
    os.makedirs(staging)

    # Safety net: keep an image in the version if the built site still references it
    # under its original name (e.g. from a template or a script the rewrite does not cover)
    still_referenced = set()
    by_basename = {}
    for url in _shared:
        by_basename.setdefault(posixpath.basename(url), []).append(url)
    for dirpath, _, filenames in os.walk(config.site_dir):
        for name in filenames:
            if name.endswith((".html", ".css")):
                with open(os.path.join(dirpath, name), encoding="utf-8", errors="ignore") as f:
                    links = [attribute or css_url for attribute, css_url in LINK_RE.findall(f.read())]
                for link in links:
                    basename = posixpath.basename(unquote(link.strip("'\" ").split("#")[0].split("?")[0]))
                    still_referenced.update(by_basename.get(basename, []))

    moved_bytes = 0
    for url, shared_name in _shared.items():
        file = _images[url]
        shutil.copy2(file.abs_src_path, os.path.join(staging, shared_name))
        if url in still_referenced:
            log.info("Image '%s' is still referenced under its original name, kept in the version", url)
            continue
        moved_bytes += os.path.getsize(file.abs_dest_path)
        os.remove(file.abs_dest_path)

    log.info("Shared assets: %d images moved to %s (%.1f MB)", len(_shared), STAGING_DIR, moved_bytes / 1024 / 1024)
