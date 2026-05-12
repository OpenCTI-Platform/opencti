---
applyTo: "docs/**"
description: "OpenCTI documentation writing style, page structure, and MkDocs conventions"
---

# Documentation (docs/)

## Scope
The `docs/` directory is a **MkDocs Material** site for the OpenCTI platform documentation, published at [docs.opencti.io](https://docs.opencti.io).

## Architecture

### Tech Stack
- **Static site generator**: MkDocs with Material for MkDocs
- **Content format**: Markdown (`.md`) files in `docs/docs/`
- **Config**: `mkdocs.yml` at `docs/` root
- **Deployment**: GitHub Pages

### Repository Structure
```
docs/
├── docs/             → Markdown source files
│   ├── administration/
│   ├── deployment/
│   ├── development/
│   ├── reference/
│   └── usage/
├── overrides/        → MkDocs Material template overrides
├── mkdocs.yml        → MkDocs configuration and nav tree
└── requirements.txt  → Python dependencies
```

## Docs Commands

Run commands from `docs/` at repository root.

```bash
# Install dependencies
pip install -r requirements.txt

# Run docs locally
mkdocs serve

# Build static site
mkdocs build

# Deploy a version
mike deploy --push <version>

# Deploy a version and update latest alias
mike deploy --push --update-aliases <version> latest

# List deployed versions
mike list
```

## Writing Style Rules

### Voice and Tone
- Use **active voice** and **present tense**: "Run the command" ✅, not "The command should be run" ❌.
- Be clear, concise, and pedagogical. Avoid unnecessary jargon.
- Capitalize proper nouns and platform concepts: **OpenCTI**, **MITRE ATT&CK**, **STIX**, **REST API**, **Indicator**, **Observable**, **Report**, **Threat Actor**, **Playbook**.
- Explain acronyms on first use: e.g., **TTP (Tactics, Techniques, and Procedures)**, **IOC (Indicator of Compromise)**.

### Page Structure (Usage-Driven)
Every page should follow this structure:

1. **What is this?** — Define the concept.
2. **Why use it?** — Explain the value and context.
3. **How do I do it?** — Provide clear, ordered steps.
4. **Example** — Add a realistic case (screenshot, workflow, config snippet).
5. **What's next?** — Suggest related pages or next steps.

Always start with usage and benefits first, then show the execution.

### Markdown Conventions
- Start each page with a short introduction summarizing what the page covers.
- Use `##` for sections, `###` for subsections — keep headings consistent.
- Use **numbered lists** for sequential steps.
- Use **tables** for parameters, config options, and field descriptions.
- Use **code blocks** with syntax highlighting for commands and configs.
- Use **admonitions** for emphasis:
  - `!!! warning` for warnings
  - `!!! note` for tips and informational callouts
  - `!!! tip` for best practices

### Filenames and URIs
- Use **hyphens** (`-`) in filenames: `threat-actor-group.md` ✅
- **Never** use underscores (`_`): `threat_actor_group.md` ❌

### Images
- Store images in `docs/docs/[SECTION]/assets/`.
- Use descriptive filenames: `report-creation-form.png`.
- Optimize for web (compressed, < 1 MB).

## When Adding a New Page

1. Create the `.md` file in the appropriate `docs/docs/` subdirectory.
2. Add the page to the `nav` section in `docs/mkdocs.yml`.
3. Add cross-links from related pages.
4. Follow the usage-driven page structure above.
