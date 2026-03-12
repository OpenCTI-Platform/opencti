# AI Instruction Architecture Guide

This guide details the "Instruction Set Architecture" used in this repository to effectively guide AI coding assistants (like GitHub Copilot). It provides a structured approach to context management, role definition, and task execution.

## 1. Directory Structure

The configuration lives in the `.github` directory, separating instructions by type and scope.

```
.github/
├── copilot-instructions.md       # Root entry point (Global Context)
├── instructions/                 # Context-specific technical documentation
│   ├── backend.instructions.md
│   ├── frontend.instructions.md
│   └── feature-*.instructions.md
├── skills/                       # Procedural playbooks for complex tasks
│   └── <skill-name>/
│       └── SKILL.md
├── prompts/                      # Task-specific prompts (debugging, analysis)
│   └── *.prompt.md
└── copilot/                      # AI Tool Configuration
    └── mcp.json
```

## 2. Root Instruction (`copilot-instructions.md`)

This file acts as the **primary system prompt** or **context root** for the AI.

**Key Responsibilities:**
- **Deep-Dive References**: A "Read-Before-Touch" index pointing to specialized instruction files. This teaches the AI *where* to look for details instead of hallucinating.
- **Skill Index**: Lists available procedural skills (`skills/` directory).
- **Project Overview**: High-level architecture and workspace structure.
- **Global Commands**: Essential CLI commands for build, test, and database operations.
- **Code Conventions**: Universal rules (e.g., naming conventions, forbidden patterns) that apply across the entire repo.

**Example Pattern:**
```markdown
# Project Instructions

> **Deep-dive references** — read the relevant doc before touching the related code:
> - [Frontend Architecture](.github/instructions/frontend.instructions.md)
> ...

> **Copilot Skills** (`.github/skills/`) — procedural playbooks:
> - `create-domain-module` — scaffold a complete backend module
> ...
```

## 3. Specialized Instruction Files (`instructions/*.instructions.md`)

These files provide **context-specific rules** that apply only to certain parts of the codebase.

**Key Features:**
- **Frontmatter Targeting (`applyTo`)**: Uses glob patterns to tell the AI/System explicitly which files these instructions govern.
- **Standardized Sections**:
    - **Scope**: What the module/feature does.
    - **Architecture**: Database schema, API design, component hierarchy.
    - **Patterns to Follow**: Explicit "Do this, don't do that" examples for the specific domain.

**Example Pattern (`instructions/feature-name.instructions.md`):**
```markdown
---
applyTo: "**/path/to/feature/**"
description: "Feature scope, architecture, and implementation patterns"
---

# Feature Name

## Scope
...

## Architecture
...

## Patterns to follow
...
```

## 4. Procedural Skills (`skills/<name>/SKILL.md`)

"Skills" are **procedural playbooks** for complex, multi-step tasks that require modifying multiple files in a specific order.

**Key Features:**
- **Structured as a Script**: Steps 1, 2, 3...
- **Prerequisites**: Information the AI must gather from the user before starting.
- **Templates**: Code blocks with placeholders for the AI to fill.

**Example Pattern:**
```markdown
# Create Domain Module

## Prerequisites
- Domain name
- Scope (tenant/org)
- ...

## Procedure

### Step 1 — Create Schema
...
### Step 2 — Create Repository
...
```

## 5. Task-Specific Prompts (`prompts/*.prompt.md`)

These are **pre-defined prompts** for recurring tasks, such as debugging specific types of issues or performing security reviews.

**Key Features:**
- **Frontmatter**: Defines the `mode` (e.g., `agent`) and `description`.
- **Step-by-Step Analysis**: Guides the AI through a logical troubleshooting or analysis process.

**Example Pattern:**
```markdown
---
mode: agent
description: Diagnose and fix specific issue type
---

# Debug [Issue Type]

## Steps
1. Identify the affected module...
2. Check the schema...
3. ...
```

## 6. Tool Configuration (`copilot/mcp.json`)

If using the Model Context Protocol (MCP), this file configures external tools (like database access or web fetchers) that the AI can use to gather context or perform actions.

**Example Pattern:**
```json
{
  "mcpServers": {
    "postgres": { ... },
    "fetch": { ... }
  }
}
```

## Summary of Patterns to Replicate

1.  **Centralize Global Rules**: Keep universal conventions in one root file (`copilot-instructions.md`).
2.  **Modularize Technical Context**: Split detailed documentation into `instructions/` files.
3.  **Target Context with Glob Patterns**: Use `applyTo` frontmatter to map instructions to code paths.
4.  **Templatize Complex Workflows**: Use `skills/` for multi-step generation tasks.
5.  **Standardize Prompting**: Use `prompts/` for consistent debugging/analysis workflows.
6.  **"Read-First" Philosophy**: Explicitly instruct the AI to read relevant documentation before modifying code.
