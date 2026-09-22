/**
 * THE authoritative count of the surfaces this migration talks about.
 *
 * Every figure quoted in the PR body, in PAPER-GAP-INVENTORY.md and in
 * LIBRARY-FEEDBACK.md comes from running this script — not from a grep. It
 * imports the same analyser the conformity gate uses (`lib/jsx-opening-tags.mjs`),
 * so a count and a guard cannot disagree about what a call site is.
 *
 * Run: node fds-migration/scripts/count-surfaces.mjs
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { openingTags, importOrigin } from "./lib/jsx-opening-tags.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = join(HERE, "..", "..", "opencti-platform", "opencti-front", "src");

const files = [];
const walk = (dir) => {
  for (const entry of readdirSync(dir)) {
    if (entry === "__generated__" || entry === "node_modules") continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full);
    else if (/\.(tsx|jsx)$/.test(entry)) files.push(full);
  }
};
walk(SRC);

const rel = (f) => f.slice(SRC.length + 1);
const tally = {
  paperLibrary: { sites: 0, files: new Set() },
  paperMui: { sites: 0, files: new Set() },
  cardWrapper: { sites: 0, files: new Set(), title: 0, composedTitle: 0, action: 0, link: 0, sx: 0, outlined: 0 },
  cardMui: { sites: 0, files: new Set() },
};

for (const file of files) {
  const content = readFileSync(file, "utf8");

  const paperFrom = importOrigin(content, "Paper");
  const paperTags = openingTags(content, "Paper");
  if (paperTags.length) {
    const bucket = paperFrom === "library" ? tally.paperLibrary : tally.paperMui;
    bucket.sites += paperTags.length;
    bucket.files.add(rel(file));
  }

  const cardFrom = importOrigin(content, "Card");
  const cardTags = openingTags(content, "Card");
  if (cardTags.length) {
    if (cardFrom === "mui") {
      tally.cardMui.sites += cardTags.length;
      tally.cardMui.files.add(rel(file));
    } else if (cardFrom === "product") {
      tally.cardWrapper.sites += cardTags.length;
      tally.cardWrapper.files.add(rel(file));
      for (const tag of cardTags) {
        if (/\btitle\s*=/.test(tag)) tally.cardWrapper.title += 1;
        if (/\baction\s*=/.test(tag)) tally.cardWrapper.action += 1;
        if (/\bto\s*=|\bonClick\s*=/.test(tag)) tally.cardWrapper.link += 1;
        if (/\bsx\s*=/.test(tag)) tally.cardWrapper.sx += 1;
        if (/\bvariant\s*=\s*(["'])outlined\1/.test(tag)) tally.cardWrapper.outlined += 1;
        const m = tag.match(/\btitle=\{([\s\S]*)\}/);
        if (m && /<|\?|&&|\.map\(/.test(m[1])) tally.cardWrapper.composedTitle += 1;
      }
    }
  }
}

const line = (label, value) => console.log(`${label.padEnd(52)} ${String(value).padStart(5)}`);
console.log(`Files scanned: ${files.length} (.tsx/.jsx under opencti-front/src, __generated__ excluded)\n`);
console.log("PAPER");
line("  sites importing Paper from the library", tally.paperLibrary.sites);
line("  files", tally.paperLibrary.files.size);
line("  sites still importing MUI's Paper", tally.paperMui.sites);
line("  files", tally.paperMui.files.size);
console.log("\nCARD (product wrapper components/common/card/Card)");
line("  sites", tally.cardWrapper.sites);
line("  files", tally.cardWrapper.files.size);
line("  with title=", tally.cardWrapper.title);
line("    of which a composed node", tally.cardWrapper.composedTitle);
line("  with action=", tally.cardWrapper.action);
line("  card-links (to / onClick)", tally.cardWrapper.link);
line("  with sx=", tally.cardWrapper.sx);
line("  with variant=\"outlined\"", tally.cardWrapper.outlined);
console.log("\nCARD (MUI's own, out of the wrapper's scope)");
line("  sites", tally.cardMui.sites);
line("  files", tally.cardMui.files.size);
for (const f of tally.cardMui.files) console.log(`    ${f}`);
