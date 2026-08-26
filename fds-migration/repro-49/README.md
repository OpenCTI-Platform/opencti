# repro-49 — Select keeps `pointer-events: none` on `<body>` after Tab

Minimal reproduction for LIBRARY-FEEDBACK #49. React plus the built design
system, **no OpenCTI code**.

## Verdict: CONFIRMED, on exactly one path

| Component | select | Escape | click outside | Tab | unmount while open |
|---|---|---|---|---|---|
| library `Select`   | restored | restored | restored | **LEAKS** | restored |
| library `Combobox` | untouched | untouched | untouched | untouched | untouched |

Identical in **dark and light**. `Combobox` is immune because it mounts
`PopoverPrimitive.Root` with `modal: false`, which never reaches the code that
writes the property.

## The faulty path, named

A real `Tab` on an **open** `Select` moves focus out **without closing the
panel**:

```
stillOpen=true  triggerExpanded=true  activeElement=DIV  popperLayers=1
body pointer-events = none   (inline)
→ clicking anything else: locator.click Timeout, clicked=0
```

So the leak is not a failed cleanup. The panel is legitimately still open and
`@radix-ui/react-dismissable-layer` is correct to keep the property set. The
defect is that focus leaves an open modal panel and nothing dismisses it.

## Attribution: upstream of the design system

The same test against **raw `@radix-ui/react-select`**, no design system:

```
[library Select]   stillOpen=true bodyPE=none laterClickBlocked=true
[raw Radix Select] stillOpen=true bodyPE=none laterClickBlocked=true
```

Identical. `SelectContent` passes only `position`, `sideOffset` and `className`
into `SelectPrimitive.Content` and disables no dismissal. **The behaviour is
Radix's.** What belongs to the design system is the *exposure*: it ships `Select`
on a modal primitive with no mitigation, while its own `Combobox` opted out with
`modal: false`. Fixing it is a library decision — dismiss on focus-out, handle
Tab, or make Select non-modal like Combobox — not a product workaround.

## Run it

```bash
# 1. point the aliases at a checkout that has the deps installed
sed -i '' "s|<OPENCTI_FRONT>|/abs/path/to/opencti-platform/opencti-front|g" vite.config.mjs
# 2. serve
"$FRONT/node_modules/.bin/vite" --config vite.config.mjs      # :4300
# 3. red before fix — 2 of 12 fail, both `Tab blur`, one per theme
"$FRONT/node_modules/.bin/playwright" test --config playwright.config.mjs
```

Expected output before a fix:

```
2 failed
  theme: dark  › select — close by Tab blur   Expected "auto"  Received "none"
  theme: light › select — close by Tab blur   Expected "auto"  Received "none"
10 passed
```

## NOT the cause of the two failing OpenCTI E2E specs

Stated because it would be easy to assume. `backgroundTask` and `rfis` contain no
`Tab` press — verified by grep over both specs and their page models. This leak is
real and worth fixing on its own; the CI failures need a separate diagnosis, and
the current evidence for them is in LIBRARY-FEEDBACK #49.

---

## Also hosts the `createOption` diagnostics

`create-row.spec.mjs` and `create-regex.spec.mjs` answer two questions about the
library's create affordance, raised by `incidentResponse.spec.ts:298` failing on
CI while `report.spec.ts` passes the same flow.

**Does an identity `filterOptions` suppress the create row?** No.
`ExternalReferencesField` passes `filterOptions={(options) => options}` because
its search is server-side, which made this the first suspect.

```
[identity filterOptions]      options=["Create ‘brand new value’","Alpha","Bravo","Charlie"]  → PRESENT
[default filtering (control)] options=["Create ‘brand new value’"]                            → PRESENT
```

**Does the page model's matcher fail on a multi-word value?** No. The two specs
differ in exactly that — `'external ref'` passes, `'external ref incident
response'` times out — so the matcher was the second suspect.

```
"Create ‘external ref’"                     regex matches: 1  click: SUCCEEDED
"Create ‘external ref incident response’"   regex matches: 1  click: SUCCEEDED
```

Both hypotheses are dead. The cause of that spec's failure is still open.
