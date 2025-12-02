// eslint-disable-next-line max-classes-per-file
import { parser as jsParser } from '@lezer/javascript';
import type { Data, Options } from 'ejs';
import { render } from 'ejs';
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
  maxExecutedStatementCount?: number | undefined,
  maxExecutionDuration?: number | undefined,
  yieldMethod?: (() => Promise<void>) | undefined,
  useNotificationTool?: boolean | undefined,
};

export type SafeRenderOptions = Options & SafeOptions;

export const safeReservedPrefix = '____safe____';
export const safeName = (name: 'statement' | 'property' | 'Object' ) => `${safeReservedPrefix}${name}`;

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
]);

const authorizeGlobals = {
  undefined: true,
  Object: safeName('Object'),
  Boolean: true,
  Number: true,
  BigInt: true,
  Date: true,
  RegExp: true,
  String: true,
  JSON: true,
  Math: true,
  Infinity: true,
  isFinite: true,
  NaN: true,
  isNaN: true,
  parseFloat: true,
  parseInt: true,
  encodeURI: true,
  encodeURIComponent: true,
  decodeURI: true,
  decodeURIComponent: true,
};

const forbiddenGlobals = [
  'eval',
  'globalThis',
  'import',
  'Function',
  'Proxy',
  'Reflect',
];

const noop = () => {};

const createSafeContext = (async: boolean, { maxExecutedStatementCount = 0, maxExecutionDuration = 0, yieldMethod }: SafeOptions) => {
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

  return {
    [safeName('statement')]: async
      ? async () => {
        checkMaxExecutedStatementCount();
        checkMaxExecutionDuration();
        await yieldMethod?.();
      }
      : () => {
        checkMaxExecutedStatementCount();
        checkMaxExecutionDuration();
      },

    [safeName('property')]: (propertyName: unknown) => {
      if (typeof propertyName === 'string' && (propertyName.startsWith(safeReservedPrefix) || forbiddenProperties.has(propertyName))) {
        throw new VerifierIllegalAccessError(`Forbidden property access ${JSON.stringify({ propertyName })}`);
      }
      return propertyName;
    },

    [safeName('Object')]: Object.freeze({
      keys: Object.keys,
      values: Object.values,
      entries: Object.entries,
      fromEntries: Object.fromEntries,
      assign: (target: Record<string, unknown>, ...sources: Record<string, unknown>[]) => {
        sources
          .filter((src) => src && typeof src === 'object')
          .forEach((src) => {
            Object.entries(src).forEach(([key, value]) => {
              if (key.startsWith(safeReservedPrefix) || forbiddenProperties.has(key)) {
                throw new VerifierIllegalAccessError(`Forbidden property access ${JSON.stringify({ propertyName: key })}`);
              }
              // eslint-disable-next-line no-param-reassign
              target[key] = value;
            });
          });
        return target;
      },
    }),
  };
};

const extractEJSCode = (template: string, openTag: string, closeTag: string) => {
  const fragments: string[] = [];
  const pushFragment = (text: string, isCode: boolean) => {
    if (text.length > 0) {
      if (isCode) {
        fragments.push(text);
      } else {
        // keep the same output size in order to permit to easy code edition
        // replace the first char by a semicolon, so multiple EJS tag on the same would not lead to invalid JS code
        const cleaned = `;${text.replaceAll(/[^\r\n]/g, ' ').substring(1)}`;
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
      
      if (template[startPos] === '=') {
        startPos += 1;
      }
      
      const hasStartWhitespaceControl = ['_', '-'].includes(template[startPos]);
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

      if (hasEndWhitespaceControl) {
        pushFragment(template[codeEndPos], false);
      }

      processedPos = pos;
    }
  }

  if (processedPos < template.length) {
    pushFragment(template.substring(processedPos), false);
  }

  return fragments.join('');
};

const transformTemplate = (template: string, code: string, context: string[]) => {
  context.forEach((name) => {
    if (forbiddenGlobals.includes(name) || name.startsWith(safeReservedPrefix)) {
      throw new VerifierIllegalAccessError(`Forbidden context variable ${JSON.stringify(name)}`);
    }
  });

  const allowedVars = new Map(Object.entries(authorizeGlobals));
  context.forEach((c) => allowedVars.set(c, true));

  const tree = jsParser.parse(code);
  const cursor = tree.cursor();

  const fragments: string[] = [];
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

  const processParseError = () => {
    throw new VerifierParsingError('Invalid javascript');
  };

  const processThis = () => {
    throw new VerifierIllegalAccessError('Access to \'this\' is forbidden');
  };

  const isPropertyNameInBracket = () => {
    const parentType = cursor.node.parent?.type.name;
    return parentType === 'MemberExpression' || parentType === 'Property' || parentType === 'PatternProperty';
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

  const processCurlyBraceLeft = () => {
    if (cursor.node.parent?.node.name === 'Block') {
      editNode(`${nodeText()};${safeName('statement')}();`);
    }
  };

  const processImport = () => {
    throw new VerifierIllegalAccessError('Access to \'import\' is forbidden');
  };

  const processPropertyDefinitionOrName = () => {
    const rawPropertyName = nodeText();
    const isQuoted = ['"', '\'', '`'].includes(rawPropertyName[0]);
    const propertyName = isQuoted ? rawPropertyName.substring(1, rawPropertyName.length - 1) : rawPropertyName;
    if (propertyName.startsWith(safeReservedPrefix) || forbiddenProperties.has(propertyName)) {
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
    if (variableName.startsWith(safeReservedPrefix) || forbiddenGlobals.includes(variableName) || forbiddenProperties.has(variableName)) {
      throw new VerifierIllegalAccessError(`Forbidden variable definition ${JSON.stringify({ variableName })}`);
    }
    allowedVars.set(variableName, true); // TODO: should we handle the variable scope ?
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
    switch (cursor.type.name) {
      case '⚠':
        processParseError();
        break;

      case 'this':
        processThis();
        break;

      case '[':
        processBracketLeft();
        break;

      case ']':
        processBracketRight();
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

  if (templatePos < template.length) {
    fragments.push(template.substring(templatePos));
  }

  return fragments.join('');
};

export const safeRender = (template: string, data: Data, options: SafeRenderOptions = {}) => {
  const { delimiter = '%', openDelimiter = '<', closeDelimiter = '>', async = false, useNotificationTool = false } = options;
  if (useNotificationTool) {
    data.octi = new NotificationTool();
  }
  const code = extractEJSCode(template, `${openDelimiter}${delimiter}`, `${delimiter}${closeDelimiter}`);
  const safeTemplate = transformTemplate(template, code, Object.keys(data ?? {}));
  const safeContext = createSafeContext(async, options);
  return render(safeTemplate, { ...(data ?? {}), ...safeContext }, options);
};
