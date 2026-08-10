# Implementation playbook — it lives in the design-system repository

**The playbook for adopting a `@filigran/design-system` component in this
product is in `XTM-Foundation/filigran-design-system`:**

**➜ [`process/PRODUCT-IMPLEMENTATION-PLAYBOOK.md`](https://github.com/XTM-Foundation/filigran-design-system/blob/main/process/PRODUCT-IMPLEMENTATION-PLAYBOOK.md)**

## Why it is not here

It was written in the OpenAEV repository by the first pilot. This product's own
pilot then found no reference to it anywhere in this repository and had to be
told where it was — a document you have to announce is not findable. The library
is the one repository every pilot already has to look at, so the playbook moved
next to the library it describes. This file is the pointer this repository was
missing.

## What is there

| Document | What it is |
| --- | --- |
| `process/PRODUCT-IMPLEMENTATION-PLAYBOOK.md` | The playbook: prerequisites through to a green CI on a pull request shipping a library component |
| `process/PRODUCT-IMPLEMENTATION-PLAYBOOK-DEFECTS.md` | Every defect found by running the playbook against a real product, with severity and status |
| `process/artifacts/ci-design-system-secret.test.ts` | The CI credential guard to copy into a product's test suite (Step 2) |

The index of previous pilots is the table in the playbook's step 0.5, so it
travelled inside the document. **A new pilot adds its row there**, in a pull
request to the design-system repository, opened alongside the one that ships it.

## What stays here

[`LIBRARY-FEEDBACK.md`](./LIBRARY-FEEDBACK.md) — it records what this product
found missing in the library while integrating it. It is this product's
observation and it belongs to this product.

The rest of `fds-migration/` is unchanged: it is this repository's own migration
state, mapping and log, not the general playbook.
