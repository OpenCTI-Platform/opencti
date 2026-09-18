// Components that clone their single child and attach a ref to it. The child
// must therefore be able to hold a ref, and a Fragment cannot: the ref is never
// populated and the component silently does nothing. MUI `Tooltip`, for
// instance, gates its popper on the resolved node
// (`open: childNode ? open : false`), so `<Tooltip><>…</></Tooltip>` never
// shows a tooltip at all. See issue #18353.
//
// React 19.3 makes the same mistake throw instead of staying silent: Fragment
// Refs call the ref with a `FragmentInstance`, which has no DOM methods.
const REF_ANCHOR_COMPONENTS = new Set([
  'ClickAwayListener',
  'Collapse',
  'Fade',
  'Grow',
  'Slide',
  'Tooltip',
  'Zoom',
]);

// `<Foo>` -> 'Foo', `<Name.Space.Foo>` -> 'Foo', `<ns:foo>` -> null.
const elementName = (jsxElement) => {
  const { name } = jsxElement.openingElement;
  if (name.type === 'JSXIdentifier') return name.name;
  if (name.type === 'JSXMemberExpression') return name.property?.name ?? null;
  return null;
};

// `<>`, `<Fragment>` and `<React.Fragment>` are all the same hole.
const isFragment = (node) => {
  if (node.type === 'JSXFragment') return true;
  if (node.type !== 'JSXElement') return false;
  return elementName(node) === 'Fragment';
};

const isMeaningfulChild = (child) => !(child.type === 'JSXText' && child.value.trim() === '');

const rule = {
  meta: {
    type: 'problem',
    docs: {
      description: 'Disallow a Fragment as the child of a component that attaches a ref to it',
    },
    schema: [],
    messages: {
      fragmentAnchor: '`{{ component }}` attaches a ref to its child, and a Fragment cannot hold one, so it will silently do nothing. Wrap the content in an element instead (a `span`, a `div`, or a `Stack`).',
    },
  },
  create: (context) => {
    return {
      JSXElement(node) {
        const component = elementName(node);
        if (!component || !REF_ANCHOR_COMPONENTS.has(component)) {
          return;
        }
        const children = node.children.filter(isMeaningfulChild);
        if (children.length !== 1 || !isFragment(children[0])) {
          return;
        }
        context.report({
          node: children[0],
          messageId: 'fragmentAnchor',
          data: { component },
        });
      },
    };
  },
};

export default rule;
