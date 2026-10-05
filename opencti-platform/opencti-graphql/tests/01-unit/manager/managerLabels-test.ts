import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

// Settings > Parameters renders t_i18n(module.id) for every manager reported by the cluster: a manager id without
// a label in a language file reaches the screen as a raw id. Managers are collected from the sources, nothing is
// imported or started: the legacy managers whose status() clusterManager.ts reports, and every registerManager() call.

const GRAPHQL_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const SRC_ROOT = path.join(GRAPHQL_ROOT, 'src');
const LANG_ROOT = path.resolve(GRAPHQL_ROOT, '../opencti-front/lang');
const CLUSTER_MANAGER_FILE = path.join(SRC_ROOT, 'manager', 'clusterManager.ts');
const SOURCE_EXTENSIONS = ['.ts', '.js'];

// text: comments blanked; code: comments and the content of string, template and regex literals blanked.
// Both keep the offsets of the original file.
type SourceFile = { file: string; text: string; code: string };
type Expression = { literal: string } | { identifier: string };
type Resolved = { kind: 'string'; value: string } | { kind: 'object'; source: SourceFile; openIndex: number };
type ManagerId = { id: string; file: string };

const relative = (file: string) => path.relative(GRAPHQL_ROOT, file).split(path.sep).join('/');

const REGEX_PRECEDERS = '(,=:[!&|?{};+-*%<>~^';

// Offset of the quote closing the string literal opened at openIndex, backslash escapes respected.
const findClosingQuote = (source: string, openIndex: number): number => {
  const quote = source[openIndex];
  let cursor = openIndex + 1;
  while (cursor < source.length && source[cursor] !== quote && source[cursor] !== '\n') {
    cursor += source[cursor] === '\\' ? 2 : 1;
  }
  return cursor;
};

const maskSource = (source: string): Omit<SourceFile, 'file'> => {
  const text = source.split('');
  const code = source.split('');
  const blank = (chars: string[], from: number, to: number) => {
    for (let index = from; index < to; index += 1) {
      if (chars[index] !== '\n') {
        chars[index] = ' ';
      }
    }
  };
  // Reads template characters from start; stops after the closing backtick or after an opening "${".
  const readTemplate = (start: number): { end: number; interpolation: boolean } => {
    let cursor = start;
    while (cursor < source.length) {
      if (source[cursor] === '\\') {
        cursor += 2;
      } else if (source[cursor] === '`') {
        blank(code, start, cursor);
        return { end: cursor + 1, interpolation: false };
      } else if (source[cursor] === '$' && source[cursor + 1] === '{') {
        blank(code, start, cursor);
        return { end: cursor + 2, interpolation: true };
      } else {
        cursor += 1;
      }
    }
    blank(code, start, cursor);
    return { end: cursor, interpolation: false };
  };
  const interpolationDepths: number[] = [];
  let braceDepth = 0;
  let lastSignificant = '';
  let index = 0;
  while (index < source.length) {
    const char = source[index];
    const next = source[index + 1];
    if (char === '/' && (next === '/' || next === '*')) {
      const close = next === '/' ? source.indexOf('\n', index) : source.indexOf('*/', index + 2);
      const end = close === -1 ? source.length : close + (next === '/' ? 0 : 2);
      blank(text, index, end);
      blank(code, index, end);
      index = end;
    } else if (char === '\'' || char === '"') {
      const cursor = findClosingQuote(source, index);
      blank(code, index + 1, cursor);
      index = cursor + 1;
      lastSignificant = char;
    } else if (char === '`' || (char === '}' && interpolationDepths.at(-1) === braceDepth)) {
      if (char === '}') {
        interpolationDepths.pop();
      }
      const template = readTemplate(index + 1);
      if (template.interpolation) {
        interpolationDepths.push(braceDepth);
      }
      index = template.end;
      lastSignificant = '`';
    } else if (char === '/' && (lastSignificant === '' || REGEX_PRECEDERS.includes(lastSignificant))) {
      let cursor = index + 1;
      let inClass = false;
      while (cursor < source.length && source[cursor] !== '\n' && (inClass || source[cursor] !== '/')) {
        if (source[cursor] === '[') {
          inClass = true;
        } else if (source[cursor] === ']') {
          inClass = false;
        }
        cursor += source[cursor] === '\\' ? 2 : 1;
      }
      blank(code, index + 1, cursor);
      index = cursor + 1;
      lastSignificant = '/';
    } else {
      if (char === '{') {
        braceDepth += 1;
      } else if (char === '}') {
        braceDepth -= 1;
      }
      if (!/\s/.test(char)) {
        lastSignificant = char;
      }
      index += 1;
    }
  }
  return { text: text.join(''), code: code.join('') };
};

const sourceCache = new Map<string, SourceFile>();
const loadSource = (file: string): SourceFile => {
  let source = sourceCache.get(file);
  if (!source) {
    source = { file, ...maskSource(readFileSync(file, 'utf8')) };
    sourceCache.set(file, source);
  }
  return source;
};

const listSourceFiles = (directory: string): string[] => readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
  const entryPath = path.join(directory, entry.name);
  if (entry.isDirectory()) {
    return listSourceFiles(entryPath);
  }
  return SOURCE_EXTENSIONS.includes(path.extname(entry.name)) ? [entryPath] : [];
});

const findClosingBrace = (code: string, openIndex: number): number => {
  let depth = 0;
  for (let index = openIndex; index < code.length; index += 1) {
    if (code[index] === '{') {
      depth += 1;
    } else if (code[index] === '}') {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
  }
  return -1;
};

const readExpression = (source: SourceFile, index: number): Expression | undefined => {
  const quote = source.text[index];
  if (quote === '\'' || quote === '"') {
    return { literal: source.text.slice(index + 1, findClosingQuote(source.text, index)).replace(/\\(.)/g, '$1') };
  }
  const identifier = /^[A-Za-z_$][\w$]*(?=\s*[,;}\n])/.exec(source.code.slice(index, index + 200))?.[0];
  return identifier ? { identifier } : undefined;
};

// Offset of the value of the "id" property declared directly inside the object literal opened at openIndex.
const findTopLevelIdValue = (source: SourceFile, openIndex: number): number => {
  const closeIndex = findClosingBrace(source.code, openIndex);
  let depth = 0;
  for (let index = openIndex; index < closeIndex; index += 1) {
    const char = source.code[index];
    if ('{(['.includes(char)) {
      depth += 1;
    } else if ('})]'.includes(char)) {
      depth -= 1;
    } else if (depth === 1 && !/[\w$.]/.test(source.code[index - 1])) {
      const property = /^id\s*:\s*/.exec(source.code.slice(index, index + 20));
      if (property) {
        return index + property[0].length;
      }
    }
  }
  return -1;
};

const resolveModulePath = (fromFile: string, specifier: string): string | undefined => {
  const base = path.resolve(path.dirname(fromFile), specifier);
  const withoutJs = base.replace(/\.js$/, '');
  const candidates = [
    base,
    ...SOURCE_EXTENSIONS.map((extension) => `${withoutJs}${extension}`),
    ...SOURCE_EXTENSIONS.map((extension) => path.join(base, `index${extension}`)),
  ];
  return candidates.find((candidate) => existsSync(candidate) && statSync(candidate).isFile());
};

const findNamedImport = (source: SourceFile, name: string): { file: string; name: string } | undefined => {
  for (const [, specifiers, importPath] of source.text.matchAll(/import\s*(?:type\s+)?\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]/g)) {
    for (const specifier of specifiers.split(',')) {
      const [imported, local] = specifier.trim().replace(/^type\s+/, '').split(/\s+as\s+/);
      if ((local ?? imported) === name && importPath.startsWith('.')) {
        const target = resolveModulePath(source.file, importPath);
        return target ? { file: target, name: imported } : undefined;
      }
    }
  }
  return undefined;
};

// Resolves a constant to its string value or its object literal, following aliases and relative named imports.
const resolveIdentifier = (source: SourceFile, name: string, hops = 0): Resolved | undefined => {
  if (hops > 8) {
    return undefined;
  }
  const declaration = new RegExp(`\\b(?:const|let|var)\\s+${name.replace(/\$/g, '\\$')}\\b[^=;]*=\\s*`).exec(source.code);
  if (!declaration) {
    const imported = findNamedImport(source, name);
    return imported ? resolveIdentifier(loadSource(imported.file), imported.name, hops + 1) : undefined;
  }
  const valueIndex = declaration.index + declaration[0].length;
  if (source.code[valueIndex] === '{') {
    return { kind: 'object', source, openIndex: valueIndex };
  }
  const value = readExpression(source, valueIndex);
  if (value && 'literal' in value) {
    return { kind: 'string', value: value.literal };
  }
  return value ? resolveIdentifier(source, value.identifier, hops + 1) : undefined;
};

const resolveId = (source: SourceFile, valueIndex: number): string | undefined => {
  const value = valueIndex === -1 ? undefined : readExpression(source, valueIndex);
  if (!value) {
    return undefined;
  }
  if ('literal' in value) {
    return value.literal;
  }
  const resolved = resolveIdentifier(source, value.identifier);
  return resolved?.kind === 'string' ? resolved.value : undefined;
};

const collectRegisteredManagers = (errors: string[]): ManagerId[] => listSourceFiles(SRC_ROOT).flatMap((file) => {
  const source = loadSource(file);
  return [...source.code.matchAll(/\bregisterManager\(\s*(\{|[A-Za-z_$][\w$]*)/g)].flatMap((match): ManagerId[] => {
    const argument = match[1];
    let id: string | undefined;
    if (argument === '{') {
      id = resolveId(source, findTopLevelIdValue(source, (match.index ?? 0) + match[0].length - 1));
    } else {
      const definition = resolveIdentifier(source, argument);
      id = definition?.kind === 'object' ? resolveId(definition.source, findTopLevelIdValue(definition.source, definition.openIndex)) : undefined;
    }
    if (!id) {
      errors.push(`${relative(file)}: cannot resolve the manager id of registerManager(${argument === '{' ? '{ ... }' : argument})`);
      return [];
    }
    return [{ id, file: relative(file) }];
  });
});

const collectClusterManagers = (errors: string[]): ManagerId[] => {
  const cluster = loadSource(CLUSTER_MANAGER_FILE);
  const names = [...new Set([...cluster.code.matchAll(/(?<![\w$.])([A-Za-z_$][\w$]*)\.status\(/g)].map(([, name]) => name))];
  return names.flatMap((name): ManagerId[] => {
    const importPath = new RegExp(`import\\s+${name}\\s+from\\s+['"]([^'"]+)['"]`).exec(cluster.text)?.[1];
    const file = importPath ? resolveModulePath(CLUSTER_MANAGER_FILE, importPath) : undefined;
    let id: string | undefined;
    if (file) {
      const source = loadSource(file);
      const status = /(?<![\w$.])status\s*(?::\s*(?:async\s*)?\(|\()/.exec(source.code);
      const bodyOpen = status ? source.code.indexOf('{', status.index) : -1;
      const bodyClose = bodyOpen === -1 ? -1 : findClosingBrace(source.code, bodyOpen);
      const property = bodyClose === -1 ? null : /(?<![\w$.])id\s*:\s*/.exec(source.code.slice(bodyOpen, bodyClose));
      id = property ? resolveId(source, bodyOpen + property.index + property[0].length) : undefined;
    }
    if (!file || !id) {
      errors.push(`${relative(CLUSTER_MANAGER_FILE)}: cannot resolve the manager id reported by ${name}.status()`);
      return [];
    }
    return [{ id, file: relative(file) }];
  });
};

const readDictionary = (file: string): Record<string, unknown> => (existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : {});

// The guard needs the monorepo checkout: a missing directory fails the first test instead of skipping the guard.
const LANG_BACK_ROOT = path.join(LANG_ROOT, 'back');
const LANGUAGES = (existsSync(LANG_BACK_ROOT) ? readdirSync(LANG_BACK_ROOT) : [])
  .filter((file) => file.endsWith('.json'))
  .map((file) => path.basename(file, '.json'))
  .sort();

// Same merge as AppIntlProvider: lang/back first, lang/front on top.
const DICTIONARIES = new Map(LANGUAGES.map((language) => [language, {
  ...readDictionary(path.join(LANG_ROOT, 'back', `${language}.json`)),
  ...readDictionary(path.join(LANG_ROOT, 'front', `${language}.json`)),
}]));

const resolutionErrors: string[] = [];
const MANAGERS = [...collectClusterManagers(resolutionErrors), ...collectRegisteredManagers(resolutionErrors)];
const MANAGER_IDS = [...new Set(MANAGERS.map(({ id }) => id))].sort();

describe('Manager labels of the Settings > Parameters page', () => {
  it('should find the language files of the front end', () => {
    expect(LANGUAGES, `no language file in ${LANG_BACK_ROOT}: this test reads opencti-front/lang from the monorepo checkout`).toContain('en');
  });

  it('should resolve the id of every manager', () => {
    expect(resolutionErrors).toEqual([]);
  });

  it('should collect the managers of both registration paths', () => {
    // RULE_ENGINE and HISTORY_MANAGER are reported by clusterManager.ts, the others go through registerManager().
    expect(MANAGER_IDS).toEqual(expect.arrayContaining(['RULE_ENGINE', 'HISTORY_MANAGER', 'TELEMETRY_MANAGER', 'RETENTION_MANAGER', 'CATALOG_MANAGER']));
  });

  it('should label every manager in every language', () => {
    const missing = MANAGER_IDS.flatMap((id) => LANGUAGES.flatMap((language) => {
      const label = DICTIONARIES.get(language)?.[id];
      const isLabelled = typeof label === 'string' && label.trim() !== '' && label !== id;
      return isLabelled ? [] : [`${id} (${language})`];
    }));
    const hint = 'add "<ID>": "<Feature> manager" to opencti-front/lang/back/<language>.json, or fix the entry of lang/front/<language>.json, which takes precedence';
    expect(missing, `${hint}, for: ${missing.join(', ')}`).toEqual([]);
  });
});
