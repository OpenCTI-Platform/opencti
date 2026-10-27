import { stripVTControlCharacters } from 'node:util';
import { describe, expect, it } from 'vitest';
import { formatPrettyLog } from '../../../src/config/log-console-format';

const format = (info: Record<string, unknown>) => stripVTControlCharacters(formatPrettyLog(info));

describe('Pretty console log format', () => {
  it('should put the level tag and the message on the first line, then the metadata as indented JSON', () => {
    const output = format({ level: 'info', message: 'Platform started', timestamp: '2026-10-27T10:00:00.000Z', category: 'APP', port: 4000 });
    expect(output).toEqual([
      '2026-10-27T10:00:00.000Z info [APP] Platform started',
      '{',
      '  "port": 4000',
      '}',
    ].join('\n'));
  });

  it('should put the version, the category and the source/module/execution context as tags on the first line instead of the metadata', () => {
    const output = format({ level: 'info', message: 'Catalog synchronized', executionContext: 'catalog_manager', source: 'backend', module: 'catalog', category: 'APP', version: '7.0.0', count: 2 });
    expect(output).toEqual('info [7.0.0] [APP] [backend/catalog/catalog_manager] Catalog synchronized\n{\n  "count": 2\n}');
  });

  it('should only join the parts of a tag that are present', () => {
    expect(format({ level: 'info', message: 'Synchronizing', source: 'backend', executionContext: 'catalog_manager' })).toEqual('info [backend/catalog_manager] Synchronizing');
  });

  it('should not print the metadata line when every field is shown as a tag', () => {
    const output = format({ level: 'info', message: 'Platform started', category: 'APP', source: 'backend', version: '7.0.0' });
    expect(output).toEqual('info [7.0.0] [APP] [backend] Platform started');
  });

  it('should only print the first line when there is no metadata', () => {
    expect(format({ level: 'error', message: 'Boom' })).toEqual('error Boom');
  });

  it('should print the error stack below the metadata with its line breaks', () => {
    const output = format({ level: 'error', message: 'Boom', stack: 'Error: Boom\n    at test', cause: 'unknown' });
    expect(output).toEqual('error Boom\n{\n  "cause": "unknown"\n}\nError: Boom\n    at test');
  });

  it('should colorize the level tag when colors are enabled', () => {
    const previousForceColor = process.env.FORCE_COLOR;
    process.env.FORCE_COLOR = '1';
    try {
      expect(formatPrettyLog({ level: 'warn', message: 'Careful' })).toEqual('\u001b[1m\u001b[33mwarn\u001b[39m\u001b[22m Careful');
    } finally {
      if (previousForceColor === undefined) {
        delete process.env.FORCE_COLOR;
      } else {
        process.env.FORCE_COLOR = previousForceColor;
      }
    }
  });
});
