# RFCs

Design proposals that need a review before implementation, one Markdown file per RFC.

- **Location**: `docs/rfcs/` at the repository root. This folder sits next to the MkDocs source tree (`docs/docs/`) and is **not** published on docs.opencti.io; an accepted RFC that deserves public documentation gets a dedicated page under `docs/docs/development/` and a `nav` entry in `docs/mkdocs.yml`.
- **Language**: English.
- **Numbering**: `NNNN-short-title.md`, sequential, never reused.
- **Status** (header table of each RFC): `Draft` → `In review` → `Accepted` | `Rejected` → `Implemented` | `Superseded by NNNN`.
- **Code references**: cite `path:line` against the commit named in the RFC header, so reviewers can check claims.
- **Review**: open a pull request touching only the RFC file; decisions and their rationale are recorded in the RFC's decisions log before the status moves to `Accepted`.

| # | Title | Status |
|---|---|---|
| 0001 | [Platform-side connector health detection](0001-connector-health-detection.md) | Draft |
