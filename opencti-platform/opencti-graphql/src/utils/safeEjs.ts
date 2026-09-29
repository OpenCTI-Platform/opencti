import { parser as jsParser } from '@lezer/javascript';
import type { Data, Options } from 'ejs';
import { createEjsSandbox, type EjsSandbox } from './safeEjs.sandbox';
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
export const safeName = (name: 'statement' | 'statementAsync' | 'property' | 'Object' | 'iterate' | 'iterateAsync' | 'iterateKeys') => `${safeReservedPrefix}${name}`;

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
  { maxExecutedStatementCount = 0, maxExecutionDuration = 0, yieldMethod, useNotificationTool = false }: SafeOptions,
  sandboxGlobals: Record<string, unknown>,
  realm: SafeRealm,
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

  const checkProperty = (propertyName: unknown) => {
    const name = String(propertyName);
    if (name.startsWith(safeReservedPrefix) || forbiddenProperties.has(name)) {
      throw new VerifierIllegalAccessError(`Forbidden property access ${JSON.stringify({ propertyName: name })}`);
    }
    return name;
  };

  const guards = realm.makeGuards({
    statementName: safeName('statement'),
    statementAsyncName: safeName('statementAsync'),
    propertyName: safeName('property'),
    objectName: safeName('Object'),
    iterateName: safeName('iterate'),
    iterateAsyncName: safeName('iterateAsync'),
    iterateKeysName: safeName('iterateKeys'),
    checkStatement: () => {
      checkMaxExecutedStatementCount();
      checkMaxExecutionDuration();
    },
    checkStatementAsync: async () => {
      checkMaxExecutedStatementCount();
      checkMaxExecutionDuration();
      await yieldMethod?.();
    },
    checkProperty,
  });

  const globals = Object.fromEntries(
    [...authorizeGlobals.entries()].map(([name, replacement]) => [
      name,
      replacement === true ? sandboxGlobals[name] : guards[replacement],
    ]),
  );

  const safeData = realm.clone(data ?? {});

  const parts: Record<string, unknown>[] = [globals, safeData, guards];
  if (useNotificationTool) {
    const tool = new NotificationTool();
    parts.push({ octi: realm.makeOcti(realm.wrapCallback((markdownText?: string) => tool.markdownToHtml(markdownText))) });
  }
  return realm.assemble(parts);
};

/**
 * Replaces JS line and block comments in a code fragment with spaces, after normalising every
 * ECMAScript line terminator (CR, LS, PS) to LF so the verifier ends a line comment where the runtime
 * does. LS (U+2028) and PS (U+2029) are valid content inside a quoted string, where a raw LF is not,
 * so they are left untouched there (a template literal already allows a raw line terminator). One
 * character maps to one character, so positions stay aligned with the original template — which the
 * verifier edits by offset and EJS renders unchanged. This copy is used only by the lezer/AST verifier.
 */
const stripJsComments = (code: string): string => {
  const chars = code.split('');
  const inString = new Array<boolean>(chars.length).fill(false);
  const stringCursor = jsParser.parse(code).cursor();
  do {
    if (stringCursor.type.name === 'String') {
      for (let i = stringCursor.from; i < stringCursor.to; i += 1) {
        inString[i] = true;
      }
    }
  } while (stringCursor.next());
  for (let i = 0; i < chars.length; i += 1) {
    const char = chars[i];
    // A CRLF pair already ends on an LF, so only a lone CR needs normalising; rewriting the CR of a
    // CRLF would double the line terminator and break a backslash-CRLF string continuation.
    const isLoneCarriageReturn = char === '\r' && chars[i + 1] !== '\n';
    if (isLoneCarriageReturn || ((char === '\u2028' || char === '\u2029') && !inString[i])) {
      chars[i] = '\n';
    }
  }
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
    // EJS tolerates a single trailing semicolon in an output tag (<%= 1; %>). Blank it in the verifier
    // copy so the parenthesised body stays an expression instead of becoming the statement (1;).
    let lastNonBlank = end - 1;
    while (lastNonBlank >= start && /\s/.test(chars[lastNonBlank])) {
      lastNonBlank -= 1;
    }
    if (lastNonBlank >= start && chars[lastNonBlank] === ';') {
      chars[lastNonBlank] = ' ';
    }
    if (chars.slice(start, end).join('').trim().length === 0) {
      continue;
    }
    if (isBlank(start - 1) && isBlank(end) && isBlank(end + 1)) {
      chars[start - 1] = '(';
      chars[end] = ')';
      // Terminate each synthetic output expression so consecutive output tags parse as separate
      // statements rather than one call expression ((x)\n(x) would be a call), which keeps a loop's
      // braceless body limited to its own tag.
      chars[end + 1] = ';';
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
  const pendingCloseParens: number[] = [];
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

  const emitCloseParen = (pos: number) => {
    if (pos > templatePos) {
      fragments.push(template.substring(templatePos, pos));
    }
    fragments.push(')');
    templatePos = pos;
  };

  const functionNodeNames = new Set(['FunctionDeclaration', 'FunctionExpression', 'ArrowFunction', 'MethodDeclaration']);
  const guardStatement = () => {
    for (let node = cursor.node.parent; node; node = node.parent) {
      // A class static block is always synchronous (await is a syntax error there), so stop and use
      // the sync guard rather than inheriting an enclosing async function's guard.
      if (node.name === 'StaticBlock') {
        return `${safeName('statement')}()`;
      }
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
    const condition = separator.nextSibling;
    const hasCondition = condition !== null && condition.name !== ';';
    if (hasCondition) {
      // Sequence the guard before the condition with a comma, so the condition keeps its own grammar
      // and value; a '&&' prefix would break an assignment condition such as `x = values.shift()`.
      editNode(`${nodeText()}(${guardStatement()}, `);
      pendingCloseParens.push(condition.to);
    } else {
      editNode(`${nodeText()}(${guardStatement()}, true)`);
    }
  };

  const processCurlyBraceLeft = () => {
    if (cursor.node.parent?.node.name === 'Block') {
      editNode(`${nodeText()};${guardStatement()};`);
    }
  };

  // A braceless for-of/for-in body cannot carry a per-iteration guard without finding its boundary in
  // blanked code (output tags, literals, whitespace trimming all defeat that). Instead, iterate a
  // guarded generator: `of <iterable>` becomes `of ____safe____iterate(<iterable>)` and `in <object>`
  // becomes `of ____safe____iterateKeys(<object>)`. A braced body keeps its block-entry guard.
  const processForIteration = (iterateName: string, iterateAsyncName?: string) => {
    const spec = cursor.node.parent;
    if (spec?.node.name !== 'ForOfSpec' && spec?.node.name !== 'ForInSpec') {
      return;
    }
    const forStatement = spec.node.parent;
    const body = forStatement?.node.lastChild;
    const iterable = cursor.node.nextSibling;
    if (!forStatement || !body || body.name === 'Block' || !iterable) {
      return;
    }
    // `for await` needs an async guarded iterator; the sync one cannot consume an async-only iterable.
    const name = iterateAsyncName && forStatement.node.getChild('await') ? iterateAsyncName : iterateName;
    // Parenthesise the iterable so a comma (sequence) expression stays one call argument.
    editNode(`of ${name}((`);
    pendingCloseParens.push(iterable.to);
    pendingCloseParens.push(iterable.to);
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

  // The braceless for-in rewrite turns `for (TARGET in OBJ)` into `for (TARGET of ...)`. A bare
  // identifier target such as `async` is a valid for-in target but an illegal for-of one
  // (`for (async of ...)` is a SyntaxError), so its reference target must be parenthesised.
  // A declaration target (`for (const k in ...)`) is a VariableDefinition, not a VariableName, and
  // is left untouched.
  const isBracelessForInTarget = () => {
    if (cursor.node.nextSibling?.name !== 'in') {
      return false;
    }
    const spec = cursor.node.parent;
    if (spec?.node.name !== 'ForInSpec') {
      return false;
    }
    const body = spec.node.parent?.node.lastChild;
    return !!body && body.name !== 'Block';
  };

  const processVariableName = () => {
    const variableName = nodeText();
    const allowedOrReplace = allowedVars.get(variableName);
    if (!allowedOrReplace && typeof allowedOrReplace !== 'string') {
      throw new VerifierIllegalAccessError(`Forbidden variable access ${JSON.stringify({ variableName })}`);
    }
    const replacement = typeof allowedOrReplace === 'string' ? allowedOrReplace : variableName;
    if (isBracelessForInTarget()) {
      editNode(`(${replacement})`);
    } else if (typeof allowedOrReplace === 'string') {
      editNode(replacement);
    }
  };

  do {
    while (pendingCloseParens.length > 0 && cursor.node.from >= pendingCloseParens[pendingCloseParens.length - 1]) {
      emitCloseParen(pendingCloseParens.pop() as number);
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

      case 'of':
        processForIteration(safeName('iterate'), safeName('iterateAsync'));
        break;

      case 'in':
        processForIteration(safeName('iterateKeys'));
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

  while (pendingCloseParens.length > 0) {
    emitCloseParen(pendingCloseParens.pop() as number);
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

interface SafeRealm {
  clone: (value: unknown) => Record<string, unknown>;
  makeGuards: (host: Record<string, unknown>) => Record<string, unknown>;
  makeOcti: (render: unknown) => Record<string, unknown>;
  wrapCallback: <T extends (...args: never[]) => unknown>(fn: T) => T;
  assemble: (parts: Record<string, unknown>[]) => Record<string, unknown>;
}

// Rebuilds the values a template can reach inside the sandbox realm, so none of them inherits from
// the host realm's shared prototypes. The data deep copy, the guards, the Object substitute and the
// octi wrapper are all made with the sandbox's own intrinsics, so a write a template leaves on an
// inherited method dies with the per-render context instead of carrying to the next render. Function
// values pass through by reference (a worker never receives any; the main-thread callers' helpers
// keep working), so only those keep host-realm prototypes.
const createSafeRealm = (sandbox: EjsSandbox): SafeRealm => ({
  clone: sandbox.runInContext(`(() => {
    // Capture the intrinsics the clone builds with ONCE, here, before any template runs. A sandbox is
    // reused across renders (the json-mapper reuses one for a whole mapping run), and a template can
    // reassign a global it reaches — 'Array.isArray = () => false', 'Date = {}'. Reading these per call
    // would let one render corrupt a later render's data clone. The constructors a template cannot
    // reach (Map, Set, ArrayBuffer, the typed arrays, Error, the real Object) are not capturable this
    // way and do not need to be: the verifier never lets a template name them.
    // Bind the tag reader through call at build time: a template can set an own 'call' on the shared
    // Object.prototype.toString function ((({}).toString.call = ...)), and 'brand.call(value)' would
    // read that poisoned property. The bound function never re-reads .call.
    const getTag = Function.prototype.call.bind(Object.prototype.toString);
    const ownIsArray = Array.isArray;
    const ArrayCtor = Array;
    const DateCtor = Date;
    const RegExpCtor = RegExp;
    const StringCtor = String;
    const NumberCtor = Number;
    const BooleanCtor = Boolean;
    const copyInto = (source, target, seen) => {
      seen.set(source, target);
      const keys = Object.keys(source);
      for (let i = 0; i < keys.length; i += 1) {
        // Define rather than assign: an own '__proto__' key would otherwise hit the prototype setter
        // instead of being copied as data (matches structuredClone, which keeps it an own property).
        Object.defineProperty(target, keys[i], { value: clone(source[keys[i]], seen), writable: true, enumerable: true, configurable: true });
      }
      return target;
    };
    const clone = (value, seen) => {
      if (value === null || typeof value !== 'object') { return value; }
      const existing = seen.get(value);
      if (existing) { return existing; }
      const tag = getTag(value);
      if (tag === '[object Date]') { const copy = new DateCtor(value.getTime()); seen.set(value, copy); return copy; }
      if (tag === '[object RegExp]') { const copy = new RegExpCtor(value.source, value.flags); seen.set(value, copy); return copy; }
      if (tag === '[object String]') { const copy = new StringCtor(value.valueOf()); seen.set(value, copy); return copy; }
      if (tag === '[object Number]') { const copy = new NumberCtor(value.valueOf()); seen.set(value, copy); return copy; }
      if (tag === '[object Boolean]') { const copy = new BooleanCtor(value.valueOf()); seen.set(value, copy); return copy; }
      if (tag === '[object BigInt]') { const copy = Object(value.valueOf()); seen.set(value, copy); return copy; }
      if (tag === '[object ArrayBuffer]' || tag === '[object SharedArrayBuffer]') {
        const copy = new ArrayBuffer(value.byteLength);
        seen.set(value, copy);
        new Uint8Array(copy).set(new Uint8Array(value));
        return copy;
      }
      if (ArrayBuffer.isView(value)) {
        if (tag === '[object DataView]') {
          const copy = new DataView(clone(value.buffer, seen), value.byteOffset, value.byteLength);
          seen.set(value, copy);
          return copy;
        }
        const TypedArray = globalThis[value.constructor.name];
        if (TypedArray) {
          const copy = new TypedArray(clone(value.buffer, seen), value.byteOffset, value.length);
          seen.set(value, copy);
          return copy;
        }
        // A view whose constructor is not a sandbox global (e.g. a Node Buffer): copy its bytes into a
        // plain Uint8Array, which carries the length and indexed access a template can use.
        const copy = new Uint8Array(value);
        seen.set(value, copy);
        return copy;
      }
      if (ownIsArray(value)) {
        // Preserve the length so holes stay holes, and copy only existing enumerable keys (including
        // non-index properties) so a sparse or annotated array survives like structuredClone's does.
        return copyInto(value, new ArrayCtor(value.length), seen);
      }
      if (tag === '[object Map]') {
        const copy = new Map();
        seen.set(value, copy);
        for (const entry of value) { copy.set(clone(entry[0], seen), clone(entry[1], seen)); }
        return copy;
      }
      if (tag === '[object Set]') {
        const copy = new Set();
        seen.set(value, copy);
        for (const entry of value) { copy.add(clone(entry, seen)); }
        return copy;
      }
      if (tag === '[object Error]') {
        const copy = new Error(value.message);
        seen.set(value, copy);
        if (value.name !== undefined) { copy.name = value.name; }
        if (value.stack !== undefined) { copy.stack = value.stack; }
        if ('cause' in value) { copy.cause = clone(value.cause, seen); }
        return copy;
      }
      return copyInto(value, {}, seen);
    };
    return (value) => clone(value, new Map());
  })()`) as SafeRealm['clone'],
  makeGuards: sandbox.runInContext(`(host) => {
    // A host check throws a host-realm error; a template could catch it and reach the worker's shared
    // Error.prototype. Re-throw a sandbox-realm error carrying only the name and message (no host
    // object, no cause), so a caught error belongs to the per-render context.
    const rethrow = (error) => {
      const translated = new Error(error == null ? '' : error.message);
      translated.name = error == null ? 'Error' : error.name;
      return translated;
    };
    const guards = {};
    guards[host.statementName] = () => { try { host.checkStatement(); } catch (error) { throw rethrow(error); } };
    guards[host.statementAsyncName] = async () => { try { await host.checkStatementAsync(); } catch (error) { throw rethrow(error); } };
    guards[host.propertyName] = (name) => { try { return host.checkProperty(name); } catch (error) { throw rethrow(error); } };
    guards[host.objectName] = Object.freeze({
      keys: Object.keys,
      values: Object.values,
      entries: Object.entries,
      fromEntries: Object.fromEntries,
      assign: (target, ...sources) => {
        for (let i = 0; i < sources.length; i += 1) {
          const source = sources[i];
          if (source && typeof source === 'object') {
            const pairs = Object.entries(source);
            for (let j = 0; j < pairs.length; j += 1) {
              let key;
              try { key = host.checkProperty(pairs[j][0]); } catch (error) { throw rethrow(error); }
              target[key] = pairs[j][1];
            }
          }
        }
        return target;
      },
    });
    // A braceless for-of/for-in cannot carry a per-iteration guard in its body, so the loop iterates
    // a guarded generator instead: it runs the statement guard before each value, which stops a
    // runaway loop on the quota without the verifier having to find the body's boundary.
    const statement = guards[host.statementName];
    guards[host.iterateName] = function* (iterable) { for (const item of iterable) { statement(); yield item; } };
    // Delegate next()/return()/throw() to the source iterator rather than re-yielding through an async
    // generator: an async generator awaits each yielded value, which would unwrap a promise-valued
    // result that a native 'for await' preserves. An async source keeps its result verbatim; a sync
    // source is wrapped as a sync iterator so the template's own 'for await' applies the async-from-sync
    // adaptation. Either way the statement guard runs before each step and iterator closing is forwarded.
    guards[host.iterateAsyncName] = (iterable) => {
      const asyncFactory = iterable == null ? undefined : iterable[Symbol.asyncIterator];
      if (typeof asyncFactory === 'function') {
        const iterator = Reflect.apply(asyncFactory, iterable, []);
        // Capture next once (as native iteration does): re-reading it each step would let the loop
        // body overwrite the source's next and truncate the iteration.
        const nextMethod = iterator.next;
        return {
          [Symbol.asyncIterator]() { return this; },
          next(...args) { statement(); return Reflect.apply(nextMethod, iterator, args); },
          // Match native iterator closing: only a null/undefined method means "no close"; any other
          // value is invoked (and a non-callable one throws as it natively would), with the receiver
          // and the exact arguments the consumer passed.
          return(...args) { const method = iterator.return; return method == null ? Promise.resolve({ done: true, value: args[0] }) : Reflect.apply(method, iterator, args); },
          throw(...args) { const method = iterator.throw; return method == null ? Promise.reject(args[0]) : Reflect.apply(method, iterator, args); },
        };
      }
      const iterator = iterable[Symbol.iterator]();
      const nextMethod = iterator.next;
      return {
        [Symbol.iterator]() { return this; },
        next(...args) { statement(); return Reflect.apply(nextMethod, iterator, args); },
        return(...args) { const method = iterator.return; return method == null ? { done: true, value: args[0] } : Reflect.apply(method, iterator, args); },
        throw(...args) { const method = iterator.throw; if (method == null) { throw args[0]; } return Reflect.apply(method, iterator, args); },
      };
    };
    guards[host.iterateKeysName] = function* (object) { for (const key in object) { statement(); yield key; } };
    return guards;
  }`) as SafeRealm['makeGuards'],
  makeOcti: sandbox.runInContext('(render) => ({ markdownToHtml: render })') as SafeRealm['makeOcti'],
  // Wraps a host callback a template can reach (the markdown tool, the JSON escape, the include
  // barrier) in a sandbox-realm function that translates a host exception into a sandbox-realm error,
  // so a template that catches one cannot reach a host prototype through it.
  wrapCallback: sandbox.runInContext(`(fn) => (...args) => {
    try { return fn(...args); } catch (error) {
      const translated = new Error(error == null ? '' : error.message);
      translated.name = error == null ? 'Error' : error.name;
      throw translated;
    }
  }`) as SafeRealm['wrapCallback'],
  assemble: sandbox.runInContext('(parts) => Object.assign({}, ...parts)') as SafeRealm['assemble'],
});

const verifierErrorConstructors: Record<string, new (message: string) => VerifierError> = {
  VerifierParsingError,
  VerifierIllegalAccessError,
  VerifierProcessingQuotaExceededError,
};

// A render-time error leaves the sandbox as a plain shape; map a known verifier name back to its
// public type so callers' instanceof checks still hold, and keep the sandbox stack.
const restoreError = (source: { name?: string; message?: string; stack?: string }): Error => {
  // Own entries only: a template can set an error's name to an inherited key such as `toString` or
  // `constructor` and rethrow it, which would otherwise resolve to a prototype member and break
  // restoration. An unregistered name falls back to a plain Error carrying that name.
  const ErrorConstructor = source.name && Object.prototype.hasOwnProperty.call(verifierErrorConstructors, source.name)
    ? verifierErrorConstructors[source.name]
    : undefined;
  const restored = ErrorConstructor ? new ErrorConstructor(source.message ?? '') : new Error(source.message ?? '');
  if (!ErrorConstructor && source.name) {
    restored.name = source.name;
  }
  if (source.stack) {
    restored.stack = source.stack;
  }
  return restored;
};

// Renders made through the same sandbox share its globals; renders made through different
// sandboxes never do.
export const createSafeEjsSandbox = (): SafeEjsSandbox => {
  const sandbox = createEjsSandbox({ restoreError });
  const sandboxGlobals = sandbox.readGlobals(substitutedGlobals);
  const realm = createSafeRealm(sandbox);
  const includer = realm.wrapCallback(forbidInclude);
  return {
    safeRender: (template, data, options = {}) => {
      const { delimiter = '%', openDelimiter = '<', closeDelimiter = '>', async = false, useNotificationTool = false } = options;
      const code = extractEJSCode(template, `${openDelimiter}${delimiter}`, `${delimiter}${closeDelimiter}`);
      const contextVars = Object.keys(data ?? {});
      if (useNotificationTool) {
        contextVars.push('octi');
      }
      const safeTemplate = transformTemplate(template, code, contextVars, async);
      const escape = options.escape ? realm.wrapCallback(options.escape) : options.escape;
      return sandbox.render(safeTemplate, createSafeContext(data ?? {}, options, sandboxGlobals, realm), { ...options, escape, includer });
    },
  };
};

export const safeRender = (template: string, data: Data, options: SafeRenderOptions = {}) => {
  return createSafeEjsSandbox().safeRender(template, data, options);
};
