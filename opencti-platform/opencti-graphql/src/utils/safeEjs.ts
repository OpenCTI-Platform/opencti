import { parser as jsParser } from '@lezer/javascript';
import type { Data, Options } from 'ejs';
import { createEjsSandbox } from './safeEjs.sandbox';
import NotificationTool from './NotificationTool';

export abstract class VerifierError extends Error {
  name = 'VerifierError';
}

export class VerifierParsingError extends VerifierError {
  name = 'VerifierParsingError';
}

export class VerifierIllegalAccessError extends VerifierError {
  name = 'VerifierIllegalAccessError';
}

export class VerifierProcessingQuotaExceededError extends VerifierError {
  name = 'VerifierProcessingQuotaExceededError';
}

export type SafeOptions = {
  maxExecutedStatementCount?: number | undefined;
  maxExecutionDuration?: number | undefined;
  yieldMethod?: (() => Promise<void>) | undefined;
  useNotificationTool?: boolean | undefined;
};

export type SafeRenderOptions = Options & SafeOptions;

export const safeReservedPrefix = '____safe____';
export const safeName = (name: 'statement' | 'statementAsync' | 'property' | 'Object') => `${safeReservedPrefix}${name}`;

const forbiddenProperties = new Set([
  '__proto__',
  'prototype',
  'constructor',
  'arguments',
  'callee',
  'caller',
  'defineProperty',
  'defineProperties',
  'freeze',
  'seal',
  'preventExtensions',
  'getPrototypeOf',
  'setPrototypeOf',
  '__lookupGetter__',
  '__lookupSetter__',
  '__defineGetter__',
  '__defineSetter__',
]);

const isForbiddenName = (name: string) => name.includes('\\') || name.startsWith(safeReservedPrefix) || forbiddenProperties.has(name);

const authorizeGlobals = new Map<string, string | true>([
  ['undefined', true],
  ['Object', safeName('Object')],
  ['Boolean', true],
  ['Number', true],
  ['Array', true],
  ['BigInt', true],
  ['Date', true],
  ['RegExp', true],
  ['String', true],
  ['JSON', true],
  ['Math', true],
  ['Infinity', true],
  ['isFinite', true],
  ['NaN', true],
  ['isNaN', true],
  ['parseFloat', true],
  ['parseInt', true],
  ['encodeURI', true],
  ['encodeURIComponent', true],
  ['decodeURI', true],
  ['decodeURIComponent', true],
  ['escape', true],
]);

const forbiddenGlobals = [
  'eval',
  'globalThis',
  'import',
  'Function',
  'Proxy',
  'Reflect',
];

const noop = () => {};

const createSafeContext = (
  data: Data,
  { maxExecutedStatementCount = 0, maxExecutionDuration = 0, yieldMethod }: SafeOptions,
  sandboxGlobals: Record<string, unknown>,
) => {
  let executedStatementCount = 0;
  const checkMaxExecutedStatementCount = maxExecutedStatementCount > 0 ? () => {
    executedStatementCount += 1;
    if (executedStatementCount > maxExecutedStatementCount) {
      throw new VerifierProcessingQuotaExceededError(`Max executed statement count exceeded ${JSON.stringify({ maxExecutedStatementCount })}`);
    }
  } : noop;

  const startTime = performance.now();
  const checkMaxExecutionDuration = maxExecutionDuration > 0 ? () => {
    if ((performance.now() - startTime) > maxExecutionDuration) {
      throw new VerifierProcessingQuotaExceededError(`Max execution duration exceeded ${JSON.stringify({ maxExecutionDuration })}`);
    }
  } : noop;

  const sandboxObject = sandboxGlobals.Object as ObjectConstructor;

  const guards: Record<string, unknown> = {
    [safeName('statement')]: () => {
      checkMaxExecutedStatementCount();
      checkMaxExecutionDuration();
    },

    [safeName('statementAsync')]: async () => {
      checkMaxExecutedStatementCount();
      checkMaxExecutionDuration();
      await yieldMethod?.();
    },

    [safeName('property')]: (propertyName: unknown) => {
      const name = String(propertyName);
      if (name.startsWith(safeReservedPrefix) || forbiddenProperties.has(name)) {
        throw new VerifierIllegalAccessError(`Forbidden property access ${JSON.stringify({ propertyName: name })}`);
      }
      return name;
    },

    [safeName('Object')]: Object.freeze({
      keys: sandboxObject.keys,
      values: sandboxObject.values,
      entries: sandboxObject.entries,
      fromEntries: sandboxObject.fromEntries,
      assign: (target: Record<string, unknown>, ...sources: Record<string, unknown>[]) => {
        sources
          .filter((src) => src && typeof src === 'object')
          .forEach((src) => {
            sandboxObject.entries(src).forEach(([key, value]) => {
              const name = String(key); // key should already be a string, but enforce it anyway
              if (name.startsWith(safeReservedPrefix) || forbiddenProperties.has(name)) {
                throw new VerifierIllegalAccessError(`Forbidden property access ${JSON.stringify({ propertyName: name })}`);
              }

              target[name] = value;
            });
          });
        return target;
      },
    }),
  };

  const globals = Object.fromEntries(
    [...authorizeGlobals.entries()].map(([name, replacement]) => [
      name,
      replacement === true ? sandboxGlobals[name] : guards[replacement],
    ]),
  );
  return { ...globals, ...data, ...guards };
};

/**
 * Replaces JS line and block comments in a code fragment with spaces, after normalising every
 * ECMAScript line terminator (CR, LS, PS) to LF. One character maps to one character, so positions
 * stay aligned with the original template — which the verifier edits by offset and EJS renders
 * unchanged. This copy is used only by the lezer/AST verifier.
 */
const stripJsComments = (code: string): string => {
  const chars = code.replace(/[\r\u2028\u2029]/g, '\n').split('');
  const cursor = jsParser.parse(chars.join('')).cursor();
  do {
    const { name } = cursor.type;
    if (name === 'LineComment' || name === 'BlockComment') {
      for (let i = cursor.from; i < cursor.to; i += 1) {
        if (chars[i] !== '\n') {
          chars[i] = ' ';
        }
      }
    }
  } while (cursor.next());
  return chars.join('');
};

const extractEJSCode = (template: string, openTag: string, closeTag: string) => {
  const fragments: string[] = [];
  const outputRanges: Array<{ start: number; end: number }> = [];
  const pushFragment = (text: string, isCode: boolean) => {
    if (text.length > 0) {
      if (isCode) {
        fragments.push(stripJsComments(text));
      } else {
        // keep the same output size in order to permit to easy code edition
        // replace the first char by a line break, so multiple EJS tag on the same would not lead to invalid JS code
        const cleaned = `\n${text.replaceAll(/[^\r\n]/g, ' ').substring(1)}`;
        fragments.push(cleaned);
      }
    }
  };

  let pos = 0;
  let processedPos = 0;
  while (pos !== -1) {
    pos = template.indexOf(openTag, pos);
    if (pos !== -1) {
      let startPos = pos + openTag.length;

      // Skip EJS comments (<%# ... %>)
      if (template[startPos] === '#') {
        const commentStart = pos;
        pos = template.indexOf(closeTag, startPos + 1);
        if (pos === -1) {
          throw new VerifierParsingError('Unable to parse EJS template, missing close tag');
        }
        // Add non-code fragment before comment if needed
        if (commentStart > processedPos) {
          pushFragment(template.substring(processedPos, commentStart), false);
        }
        // Skip the entire comment (treat as non-code to preserve line structure)
        pushFragment(template.substring(commentStart, pos + closeTag.length), false);
        processedPos = pos + closeTag.length;
        pos = pos + closeTag.length;
        continue;
      }

      const isOutput = template[startPos] === '=' || template[startPos] === '-';
      if (isOutput) {
        startPos += 1;
      }

      const hasStartWhitespaceControl = !isOutput && template[startPos] === '_';
      let codeStartPos = startPos;
      if (hasStartWhitespaceControl) {
        codeStartPos += 1;
      }

      pos = template.indexOf(closeTag, codeStartPos);
      if (pos === -1) {
        throw new VerifierParsingError('Unable to parse EJS template, missing close tag');
      }

      const hasEndWhitespaceControl = ['_', '-'].includes(template[pos - 1]);
      let codeEndPos = pos;
      if (hasEndWhitespaceControl) {
        codeEndPos -= 1;
      }

      if (startPos > processedPos) {
        pushFragment(template.substring(processedPos, startPos), false);
      }

      if (hasStartWhitespaceControl) {
        pushFragment(template[startPos], false);
      }

      pushFragment(template.substring(codeStartPos, codeEndPos), true);
      if (isOutput) {
        outputRanges.push({ start: codeStartPos, end: codeEndPos });
      }

      if (hasEndWhitespaceControl) {
        pushFragment(template[codeEndPos], false);
      }

      processedPos = pos;
    }
  }

  if (processedPos < template.length) {
    pushFragment(template.substring(processedPos), false);
  }

  const code = fragments.join('');
  if (outputRanges.length === 0) {
    return code;
  }
  const chars = code.split('');
  const isBlank = (i: number) => i >= 0 && i < chars.length && (chars[i] === ' ' || chars[i] === '\n' || chars[i] === '\r');
  for (const { start, end } of outputRanges) {
    if (code.slice(start, end).trim().length === 0) {
      continue;
    }
    if (isBlank(start - 1) && isBlank(end) && isBlank(end + 1)) {
      chars[start - 1] = '(';
      chars[end] = ')';
      chars[end + 1] = '\n';
    }
  }
  return chars.join('');
};

const transformTemplate = (template: string, code: string, context: string[], async: boolean) => {
  context.forEach((name) => {
    if (forbiddenGlobals.includes(name) || name.startsWith(safeReservedPrefix)) {
      throw new VerifierIllegalAccessError(`Forbidden context variable ${JSON.stringify(name)}`);
    }
  });

  const allowedVars = new Map(authorizeGlobals);
  context.forEach((c) => allowedVars.set(c, true));

  const tree = jsParser.parse(code);
  const cursor = tree.cursor();

  const fragments: string[] = [];
  const pendingCloseBraces: number[] = [];
  let templatePos = 0;

  const editNode = (newNodeCode: string) => {
    const { from, to } = cursor.node;
    if (from > templatePos) {
      fragments.push(template.substring(templatePos, from));
    }
    fragments.push(newNodeCode);
    templatePos = to;
  };

  const nodeText = () => code.substring(cursor.node.from, cursor.node.to);

  const functionNodeNames = new Set(['FunctionDeclaration', 'FunctionExpression', 'ArrowFunction', 'MethodDeclaration']);
  const guardStatement = () => {
    for (let node = cursor.node.parent; node; node = node.parent) {
      if (functionNodeNames.has(node.name)) {
        return node.getChild('async') ? `await ${safeName('statementAsync')}()` : `${safeName('statement')}()`;
      }
    }
    return async ? `await ${safeName('statementAsync')}()` : `${safeName('statement')}()`;
  };

  const processParseError = () => {
    throw new VerifierParsingError('Invalid javascript');
  };

  const processThis = () => {
    throw new VerifierIllegalAccessError('Access to \'this\' is forbidden');
  };

  const processWith = () => {
    throw new VerifierIllegalAccessError('Access to \'with\' is forbidden');
  };

  const isPropertyNameInBracket = () => {
    const parentType = cursor.node.parent?.type.name;
    return parentType === 'MemberExpression' || parentType === 'Property' || parentType === 'PatternProperty';
  };

  /**
   * Returns true when the current PropertyDefinition node is a shorthand property (e.g., `{ Foo }`).
   */
  const isShorthandProperty = () => {
    const propertyNode = cursor.node.parent;
    if (!propertyNode || propertyNode.type.name !== 'Property') return false;
    return !cursor.node.nextSibling;
  };

  const processBracketLeft = () => {
    if (isPropertyNameInBracket()) {
      editNode(`${nodeText()}${safeName('property')}(`);
    }
  };

  const processBracketRight = () => {
    if (isPropertyNameInBracket()) {
      editNode(`)${nodeText()}`);
    }
  };

  // A loop body may have no braces, so the block instrumentation never reaches it. The condition
  // is the one place every loop form evaluates on each iteration.
  const processParenthesisLeft = () => {
    const parent = cursor.node.parent;
    if (parent?.node.name !== 'ParenthesizedExpression') {
      return;
    }
    const loop = parent.node.parent?.node.name;
    if (loop === 'WhileStatement' || loop === 'DoStatement') {
      editNode(`${nodeText()}${guardStatement()},`);
    }
  };

  // `for` keeps its condition in a ForSpec. The separator that precedes it is the declaration's
  // own semicolon when the loop initialises with `let`/`const`, and a ForSpec-level one otherwise.
  const forInitSeparator = () => {
    const parent = cursor.node.parent;
    if (parent?.node.name === 'VariableDeclaration' && parent.node.parent?.node.name === 'ForSpec') {
      return cursor.node.nextSibling === null ? parent.node : undefined;
    }
    if (parent?.node.name !== 'ForSpec') {
      return undefined;
    }
    for (let previous = cursor.node.prevSibling; previous; previous = previous.prevSibling) {
      if (previous.name === ';' || previous.name === 'VariableDeclaration') {
        return undefined;
      }
    }
    return cursor.node;
  };

  const processSemicolon = () => {
    const separator = forInitSeparator();
    if (!separator) {
      return;
    }
    const guard = `(${guardStatement()}, true)`;
    const hasCondition = separator.nextSibling !== null && separator.nextSibling.name !== ';';
    editNode(hasCondition ? `${nodeText()}${guard} && ` : `${nodeText()}${guard}`);
  };

  const processCurlyBraceLeft = () => {
    if (cursor.node.parent?.node.name === 'Block') {
      editNode(`${nodeText()};${guardStatement()};`);
    }
  };

  const processForIterationBody = () => {
    const spec = cursor.node.parent;
    if (spec?.node.name !== 'ForOfSpec' && spec?.node.name !== 'ForInSpec') {
      return;
    }
    const forStatement = spec.node.parent;
    const body = forStatement?.node.lastChild;
    if (!forStatement || !body || body.name === 'Block') {
      return;
    }
    editNode(`${nodeText()}{${guardStatement()};`);
    pendingCloseBraces.push(forStatement.node.to);
  };

  const processImport = () => {
    throw new VerifierIllegalAccessError('Access to \'import\' is forbidden');
  };

  const processPropertyDefinitionOrName = () => {
    const rawPropertyName = nodeText();
    const isQuoted = ['"', '\'', '`'].includes(rawPropertyName[0]);
    const propertyName = isQuoted ? rawPropertyName.substring(1, rawPropertyName.length - 1) : rawPropertyName;
    if (isForbiddenName(propertyName)) {
      throw new VerifierIllegalAccessError(`Forbidden property access ${JSON.stringify({ propertyName })}`);
    }
  };

  const processString = () => {
    const parentType = cursor.node.parent?.type.name;
    if (parentType === 'Property') {
      processPropertyDefinitionOrName();
    }
  };

  const processVariableDefinition = () => {
    const variableName = nodeText();
    const shadowsHostGlobal = !authorizeGlobals.has(variableName) && typeof (globalThis as Record<string, unknown>)[variableName] !== 'undefined';
    if (isForbiddenName(variableName) || shadowsHostGlobal) {
      throw new VerifierIllegalAccessError(`Forbidden variable definition ${JSON.stringify({ variableName })}`);
    }
    allowedVars.set(variableName, true);
  };

  const processVariableName = () => {
    const variableName = nodeText();
    const allowedOrReplace = allowedVars.get(variableName);
    if (typeof allowedOrReplace === 'string') {
      editNode(allowedOrReplace);
    } else if (!allowedOrReplace) {
      throw new VerifierIllegalAccessError(`Forbidden variable access ${JSON.stringify({ variableName })}`);
    }
  };

  do {
    while (pendingCloseBraces.length > 0 && cursor.node.from >= pendingCloseBraces[pendingCloseBraces.length - 1]) {
      const closePos = pendingCloseBraces.pop() as number;
      if (closePos > templatePos) {
        fragments.push(template.substring(templatePos, closePos));
      }
      fragments.push('}');
      templatePos = closePos;
    }
    switch (cursor.type.name) {
      case '⚠':
        processParseError();
        break;

      case 'this':
        processThis();
        break;

      case 'WithStatement':
        processWith();
        break;

      case '[':
        processBracketLeft();
        break;

      case ']':
        processBracketRight();
        break;

      case ')':
        processForIterationBody();
        break;

      case '(':
        processParenthesisLeft();
        break;

      case ';':
        processSemicolon();
        break;

      case '{':
        processCurlyBraceLeft();
        break;

      case 'DynamicImport':
      case 'ImportDeclaration':
      case 'ImportMeta':
        processImport();
        break;

      case 'PropertyDefinition':
        processPropertyDefinitionOrName();
        // Object shorthand properties do not produce a VariableName node.
        // If it's a shorthand property, we must also validate the identifier.
        if (isShorthandProperty()) {
          processVariableName();
        }
        break;

      case 'PropertyName':
        processPropertyDefinitionOrName();
        break;

      case 'String':
        processString();
        break;

      case 'VariableDefinition':
        processVariableDefinition();
        break;

      case 'VariableName':
        processVariableName();
        break;

      default:
        break;
    }
  } while (cursor.next());

  while (pendingCloseBraces.length > 0) {
    const closePos = pendingCloseBraces.pop() as number;
    if (closePos > templatePos) {
      fragments.push(template.substring(templatePos, closePos));
    }
    fragments.push('}');
    templatePos = closePos;
  }

  if (templatePos < template.length) {
    fragments.push(template.substring(templatePos));
  }

  return fragments.join('');
};

const substitutedGlobals = [...authorizeGlobals.entries()].filter(([, replacement]) => replacement === true).map(([name]) => name);

const forbidInclude = () => {
  throw new VerifierIllegalAccessError('Access to \'include\' is forbidden');
};

export interface SafeEjsSandbox {
  safeRender: (template: string, data: Data, options?: SafeRenderOptions) => string | Promise<string>;
}

// Renders made through the same sandbox share its globals; renders made through different
// sandboxes never do.
export const createSafeEjsSandbox = (): SafeEjsSandbox => {
  const sandbox = createEjsSandbox();
  const sandboxGlobals = sandbox.readGlobals([...substitutedGlobals, 'Object']);
  return {
    safeRender: (template, data, options = {}) => {
      const { delimiter = '%', openDelimiter = '<', closeDelimiter = '>', async = false, useNotificationTool = false } = options;
      if (useNotificationTool) {
        const tool = new NotificationTool();
        data.octi = { markdownToHtml: (markdownText?: string) => tool.markdownToHtml(markdownText) };
      }
      const code = extractEJSCode(template, `${openDelimiter}${delimiter}`, `${delimiter}${closeDelimiter}`);
      const safeTemplate = transformTemplate(template, code, Object.keys(data ?? {}), async);
      return sandbox.render(safeTemplate, createSafeContext(data ?? {}, options, sandboxGlobals), { ...options, includer: forbidInclude });
    },
  };
};

export const safeRender = (template: string, data: Data, options: SafeRenderOptions = {}) => {
  return createSafeEjsSandbox().safeRender(template, data, options);
};
