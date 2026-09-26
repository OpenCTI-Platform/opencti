import type { Rule } from 'eslint';
import type { Node } from 'estree';

// This rule matches on node shape rather than on node type: it reads properties only
// some node kinds carry and treats a missing one as no match. `in` is the type-level
// form of that same check, so the nodes each read accepts are unchanged.
const identifierName = (node: Node | null | undefined): string | undefined => (
  node?.type === 'Identifier' ? node.name : undefined
);

const calleeName = (node: Node): string | undefined => (
  'callee' in node ? identifierName(node.callee) : undefined
);

const leftName = (node: Node): string | undefined => (
  'left' in node ? identifierName(node.left) : undefined
);

const rule: Rule.RuleModule = {
  meta: {
    type: 'problem',
    fixable: 'code',
    docs: {
      description: 'MakeStyles should define only the classes used in the component',
    },
  },
  create: (context) => {
    const sourceCode = context.sourceCode;
    return {
      VariableDeclarator: (node) => {
        const declaredName = identifierName(node.id);
        const initCallee = node.init ? calleeName(node.init) : undefined;
        const initLeft = node.init ? leftName(node.init) : undefined;
        if ((initLeft === 'makeStyles' || initCallee === 'makeStyles') && declaredName !== 'useStyles') {
          context.report({
            node,
            message: 'MakeStyle must be declared as useStyles',
            fix: (fixer) => fixer.replaceText(node.id, 'useStyles'),
          });
        }
        if (initCallee === 'useStyles' && declaredName !== 'classes') {
          context.report({
            node,
            message: 'useStyles must be declared as classes',
            fix: (fixer) => fixer.replaceText(node.id, 'classes'),
          });
        }
      },
      ArrowFunctionExpression: (node) => {
        if (calleeName(node.parent) !== 'makeStyles') {
          return;
        }
        const { body } = node;
        if (!('properties' in body)) {
          if (!('body' in body) && !('callee' in body)) {
            context.report({ node, message: 'MakeStyles is used with no class declared' });
          }
          return;
        }
        body.properties.forEach((property) => {
          if (property.type !== 'Property') {
            return;
          }
          if (sourceCode.text.includes(`classes.${identifierName(property.key)}`)) {
            return;
          }
          const { start, end } = sourceCode.getLoc(property);
          context.report({
            node,
            message: 'Styled class is not used in component',
            fix: (fixer) => fixer.removeRange([
              sourceCode.getIndexFromLoc({ line: start.line, column: 0 }),
              sourceCode.getIndexFromLoc({ line: end.line + 1, column: 0 }),
            ]),
          });
        });
      },
    };
  },
};

export default rule;
