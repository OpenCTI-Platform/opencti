import type { Rule } from 'eslint';

const REF_ANCHOR_COMPONENTS = new Set([
  'ClickAwayListener',
  'Fade',
  'Grow',
  'Slide',
  'Tooltip',
  'Zoom',
]);

interface JsxName {
  type: string;
  name?: string;
  property?: { name?: string };
}

interface JsxChild {
  type: string;
  value?: string;
  openingElement?: { name: JsxName };
}

interface JsxElementNode extends JsxChild {
  children: JsxChild[];
}

const elementName = (node: JsxChild): string | null => {
  const name = node.openingElement?.name;
  if (!name) return null;
  if (name.type === 'JSXIdentifier') return name.name ?? null;
  if (name.type === 'JSXMemberExpression') return name.property?.name ?? null;
  return null;
};

const isFragment = (node: JsxChild): boolean => {
  if (node.type === 'JSXFragment') return true;
  if (node.type !== 'JSXElement') return false;
  return elementName(node) === 'Fragment';
};

const isMeaningfulChild = (child: JsxChild): boolean => !(child.type === 'JSXText' && (child.value ?? '').trim() === '');

const rule: Rule.RuleModule = {
  meta: {
    type: 'problem',
    docs: {
      description: 'Disallow a Fragment as the child of a component that attaches a ref to it',
    },
    schema: [],
    messages: {
      fragmentAnchor: '`{{ component }}` attaches a ref to its child and needs a DOM element there. A Fragment does not provide one, so the component either does nothing or throws at runtime. Wrap the content in an element instead (a `span`, a `div`, or a `Stack`).',
    },
  },
  create: (context) => {
    return {
      JSXElement: (jsxNode: unknown) => {
        const node = jsxNode as JsxElementNode;
        const component = elementName(node);
        if (!component || !REF_ANCHOR_COMPONENTS.has(component)) {
          return;
        }
        const children = node.children.filter(isMeaningfulChild);
        if (children.length !== 1 || !isFragment(children[0])) {
          return;
        }
        context.report({
          node: children[0] as never,
          messageId: 'fragmentAnchor',
          data: { component },
        });
      },
    } as Rule.RuleListener;
  },
};

export default rule;
