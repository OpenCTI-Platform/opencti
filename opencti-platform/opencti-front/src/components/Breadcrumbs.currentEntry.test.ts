/**
 * Sweeps every Breadcrumbs call site and requires EXACTLY ONE current entry.
 *
 * The wrapper marks the page the user is on by flagging one element `current`.
 * Nothing in the repository noticed when a site simply omitted it: the trail
 * still rendered, the last label just stopped being announced as the current
 * page, and no render test covers a site it does not import. Two pages shipped
 * that way and were found by hand during review.
 *
 * So this sweep is a source guard over the CALL SITES, not over the wrapper —
 * the wrapper's own behaviour is covered in Breadcrumbs.test.tsx. It reads the
 * `elements` prop through the TypeScript AST rather than by pattern, because
 * the array reaches the prop in three shapes across the product: written
 * inline, held in a local const, or chosen by a ternary. A regex would have to
 * guess at all three, and a site it failed to parse would read as compliant.
 *
 * Two entries in the same array flagged `current` is a defect too, not just
 * zero: the wrapper would mark two crumbs as the current page.
 *
 * An `elements` expression this file cannot resolve to at least one array
 * literal FAILS rather than passing silently. A guard that quietly skips what
 * it cannot read reports green about the sites it never looked at.
 */
import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { describe, expect, it } from 'vitest';

const SRC = path.join(__dirname, '..');

const sourceFiles = () => {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!/^(node_modules|__generated__)$/.test(entry.name)) walk(full);
      } else if (/\.(tsx|jsx)$/.test(entry.name)) out.push(full);
    }
  };
  walk(SRC);
  return out;
};

/** Every array literal an expression resolves to, within its own file. */
const arraysOf = (expr: ts.Expression | undefined, sf: ts.SourceFile): ts.ArrayLiteralExpression[] => {
  if (!expr) return [];
  if (ts.isArrayLiteralExpression(expr)) return [expr];
  if (ts.isConditionalExpression(expr)) return [...arraysOf(expr.whenTrue, sf), ...arraysOf(expr.whenFalse, sf)];
  if (ts.isIdentifier(expr)) {
    const { text } = expr;
    const found: ts.ArrayLiteralExpression[] = [];
    const scan = (node: ts.Node) => {
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === text && node.initializer) {
        found.push(...arraysOf(node.initializer, sf));
      }
      ts.forEachChild(node, scan);
    };
    scan(sf);
    return found;
  }
  return [];
};

const flagsCurrent = (node: ts.Node, sf: ts.SourceFile) => ts.isObjectLiteralExpression(node)
  && node.properties.some((p) => ts.isPropertyAssignment(p)
    && p.name.getText(sf) === 'current'
    && p.initializer.getText(sf) === 'true');

/** How many entries of one array flag themselves as the current page. */
const currentCount = (array: ts.ArrayLiteralExpression, sf: ts.SourceFile) => array.elements
  .filter((el) => (ts.isConditionalExpression(el)
    ? flagsCurrent(el.whenTrue, sf) || flagsCurrent(el.whenFalse, sf)
    : flagsCurrent(el, sf)))
  .length;

interface Site { where: string; count: number | null }

const sweep = (): Site[] => {
  const sites: Site[] = [];
  for (const file of sourceFiles()) {
    const text = fs.readFileSync(file, 'utf8');
    if (!/\bfrom\s+['"][^'"]*\/Breadcrumbs['"]/.test(text)) continue;
    const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const visit = (node: ts.Node) => {
      if ((ts.isJsxSelfClosingElement(node) || ts.isJsxOpeningElement(node))
        && node.tagName.getText(sf) === 'Breadcrumbs') {
        const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
        const where = `${path.relative(SRC, file)}:${line}`;
        const attribute = node.attributes.properties
          .find((a) => ts.isJsxAttribute(a) && a.name.getText(sf) === 'elements') as ts.JsxAttribute | undefined;
        const expression = attribute?.initializer && ts.isJsxExpression(attribute.initializer)
          ? attribute.initializer.expression
          : undefined;
        const arrays = arraysOf(expression, sf);
        if (arrays.length === 0) sites.push({ where, count: null });
        else arrays.forEach((array) => sites.push({ where, count: currentCount(array, sf) }));
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return sites;
};

describe('every Breadcrumbs call site marks its current page', () => {
  const sites = sweep();

  it('finds the call sites at all, so an empty sweep cannot pass', () => {
    // Without this, a resolver that silently stops matching turns the two
    // assertions below into vacuous truths over an empty list.
    expect(sites.length).toBeGreaterThan(150);
  });

  it('resolves the elements array at every site', () => {
    expect(sites.filter((s) => s.count === null).map((s) => s.where)).toEqual([]);
  });

  it('flags exactly one entry as current on every resolved path', () => {
    const offenders = sites
      .filter((s) => s.count !== null && s.count !== 1)
      .map((s) => `${s.where} (${s.count} current)`);
    expect(offenders).toEqual([]);
  });
});
