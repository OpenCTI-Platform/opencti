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
