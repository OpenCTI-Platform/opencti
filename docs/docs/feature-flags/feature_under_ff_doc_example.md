# Draft pages

This folder holds documentation pages that are not released yet. It is listed under `draft_docs` in `mkdocs.yml`, together with any file whose name starts with `_`:

```yaml
draft_docs: |
  feature-flags/
  _*.md
```

## What happens to a page in this folder

| Command | Page |
|---|---|
| `mkdocs serve` | Served, with a "DRAFT" marker |
| `mkdocs serve --clean` | Not served (404) |
| `mkdocs build`, `mike deploy` | Not built, never published |

Use `mkdocs serve --clean` to check what the published site will look like.

## Writing a draft page

1. Create the page in this folder, e.g. `feature-flags/my-feature.md`.
2. Run `mkdocs serve` and open it by URL: `http://127.0.0.1:8000/feature-flags/my-feature/`.
3. Do **not** add it to `nav` in `mkdocs.yml`. MkDocs drops the page from the build but keeps its nav entry, which then links to a 404 on the published site.

## Releasing a draft page

Move the page out of this folder to its final location, update any links pointing to it, and add it to `nav`.

## Not tied to `APP__ENABLED_DEV_FEATURES`

Despite the folder name, pages here are excluded from every build, whatever feature flags are enabled.

See `docs/README.md` for details.
