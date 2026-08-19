/**
 * Blanks out comments, preserving offsets and line breaks so every position and
 * line number in the result still matches the original file.
 *
 * Needed because a `<Paper>` written inside a comment is not a call site, and a
 * padding class shown in a commented EXAMPLE is not a violation. Both happened:
 * two of the "27" Paper sites were the words `<Paper>` inside the MIXED-file
 * note at the top of TokenList.tsx and UserTokenList.tsx.
 *
 * Strings and template literals are tracked, so a `//` inside a URL or a
 * `/* *\/` inside a string is not mistaken for a comment.
 *
 * @param {string} content File contents.
 * @returns {string} Same length, comments replaced by spaces.
 */
export function stripComments(content) {
  const out = content.split("");
  let i = 0;
  let quote = null;
  while (i < content.length) {
    const ch = content[i];
    const next = content[i + 1];
    if (quote) {
      if (ch === "\\") { i += 2; continue; }
      if (ch === quote) quote = null;
      i += 1;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") { quote = ch; i += 1; continue; }
    if (ch === "/" && next === "/") {
      while (i < content.length && content[i] !== "\n") { out[i] = " "; i += 1; }
      continue;
    }
    if (ch === "/" && next === "*") {
      out[i] = " "; out[i + 1] = " "; i += 2;
      while (i < content.length && !(content[i] === "*" && content[i + 1] === "/")) {
        if (content[i] !== "\n") out[i] = " ";
        i += 1;
      }
      if (i < content.length) { out[i] = " "; out[i + 1] = " "; i += 2; }
      continue;
    }
    i += 1;
  }
  return out.join("");
}

/**
 * THE declared analyser for JSX opening tags. One implementation, imported by
 * both the conformity gate and the surface counter, so a count and a guard can
 * never disagree about what a call site is.
 *
 * Why brace depth and not a regex: an `sx={{ … }}` or a `style={{ … }}` contains
 * `>` characters, so a regex that stops at the first `>` returns a fragment of
 * the tag and silently under-counts. Strings are tracked too, because a `}` can
 * live inside a template literal.
 *
 * @param {string} content File contents.
 * @param {string} tagName Component name, matched exactly (`Card` does not match
 *   `CardAccordion`, because the character after the name must be whitespace,
 *   `/` or `>`).
 * @returns {string[]} The full text of each opening tag, `<Tag …>` included.
 */
export function openingTags(rawContent, tagName) {
  // Comments are blanked first: a tag inside a comment is not a call site.
  const content = stripComments(rawContent);
  const tags = [];
  const re = new RegExp(`<${tagName}(?=[\\s/>])`, "g");
  let m;
  while ((m = re.exec(content)) !== null) {
    let depth = 0;
    let quote = null;
    let i = m.index + tagName.length + 1;
    for (; i < content.length; i += 1) {
      const ch = content[i];
      if (quote) {
        if (ch === quote && content[i - 1] !== "\\") quote = null;
      } else if (ch === '"' || ch === "'" || ch === "`") {
        quote = ch;
      } else if (ch === "{") {
        depth += 1;
      } else if (ch === "}") {
        depth -= 1;
      } else if (ch === ">" && depth === 0) {
        break;
      }
    }
    tags.push(content.slice(m.index, i + 1));
  }
  return tags;
}

/**
 * Which module a component name is imported from in a file.
 *
 * Recognises the relative form (`'./Card'`, `'../card/Card'`) as readily as the
 * long one — a filter that only matched long paths is what produced a wrong
 * Card count once, by missing three relative imports.
 *
 * @param {string} content File contents.
 * @param {string} name Imported default binding to look for.
 * @returns {"library"|"mui"|"product"|null} Origin, or null when absent.
 */
export function importOrigin(content, name) {
  const from = (re) => {
    const m = content.match(re);
    return m ? m[1] : null;
  };
  const src = from(new RegExp(`import\\s+${name}\\s*(?:,\\s*\\{[^}]*\\})?\\s*from\\s*["']([^"']+)["']`))
    ?? from(new RegExp(`import\\s*\\{[^}]*\\b${name}\\b[^}]*\\}\\s*from\\s*["']([^"']+)["']`));
  if (!src) return null;
  if (src.startsWith("@filigran/design-system")) return "library";
  if (src.startsWith("@mui/")) return "mui";
  return "product";
}
