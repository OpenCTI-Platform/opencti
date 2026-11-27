import { parser as jsParser } from '@lezer/javascript';
import { FunctionalError } from '../config/errors';

const COMMENT_NODES = ['LineComment', 'BlockComment'];

// Rendered inside one output tag: a single expression without template delimiters (comments and one trailing semicolon are fine)
export const checkJsonMapperFormula = (formula: unknown) => {
  if (formula === null || formula === undefined) {
    return;
  }
  if (typeof formula !== 'string') {
    throw FunctionalError('JSON mapper formula must be a string');
  }
  if (formula.trim().length === 0) {
    return;
  }
  if (formula.includes('<?') || formula.includes('?>')) {
    throw FunctionalError('Template delimiters are not allowed in a JSON mapper formula', { formula });
  }
  const tree = jsParser.parse(formula);
  let hasError = false;
  tree.iterate({
    enter: (node) => {
      if (node.type.isError) {
        hasError = true;
      }
    },
  });
  const statements: string[] = [];
  const top = tree.topNode.cursor();
  if (top.firstChild()) {
    do {
      if (!COMMENT_NODES.includes(top.type.name)) {
        statements.push(top.type.name);
      }
    } while (top.nextSibling());
  }
  if (hasError || statements.length !== 1 || statements[0] !== 'ExpressionStatement') {
    throw FunctionalError('A JSON mapper formula must be a single expression', { formula });
  }
};
