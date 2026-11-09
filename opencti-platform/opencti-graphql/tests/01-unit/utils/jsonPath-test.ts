import { afterAll, describe, expect, it, vi } from 'vitest';
import { Worker } from 'worker_threads';
import { JSONPath } from 'jsonpath-plus';
import conf from '../../../src/config/conf';
import { queryJsonPath, shutdownJsonPathPool } from '../../../src/utils/jsonPath.client';

describe('check queryJsonPath', () => {
  const data = {
    Event: {
      info: 'event',
      Attribute: [
        { type: 'ip-dst', value: '1.2.3.4' },
        { type: 'ip-dst', value: 'not an ip' },
        { type: 'domain', value: 'filigran.io' },
      ],
    },
  };

  afterAll(async () => {
    await shutdownJsonPathPool();
    vi.restoreAllMocks();
  });

  it('evaluates a path without script expression in process', async () => {
    const postMessageSpy = vi.spyOn(Worker.prototype, 'postMessage');
    expect(await queryJsonPath({ path: '$.Event.info', json: data, wrap: false, flatten: true })).toBe('event');
    expect(await queryJsonPath({ path: '$.Event.Attribute[*].value', json: data, flatten: true }))
      .toEqual(['1.2.3.4', 'not an ip', 'filigran.io']);
    expect(await queryJsonPath({ path: '$.Event.missing', json: data, wrap: false })).toBeUndefined();
    expect(postMessageSpy).not.toHaveBeenCalled();
    postMessageSpy.mockRestore();
  });

  it('evaluates a filter in a worker with the same result as jsonpath-plus', async () => {
    // The lookahead is not supported by RE2: the filter must keep the JavaScript regular expression semantics
    const path = '$.Event.Attribute[?(@.type == \'ip-dst\' && @.value.match(/^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)(\\.(?!$)|$)){4}$/))].value';
    const expected = JSONPath({ path, json: data, wrap: false, flatten: true });
    // A filter keeps the result wrapped even with wrap disabled, the worker must not change that
    expect(expected).toEqual(['1.2.3.4']);
    expect(await queryJsonPath({ path, json: data, wrap: false, flatten: true })).toEqual(expected);
    expect(await queryJsonPath({ path: '$.Event.Attribute[?(@.type == \'url\')]', json: data, wrap: false })).toBeUndefined();
  });

  it('rejects a script error raised in the worker', async () => {
    await expect(queryJsonPath({ path: '$.Event.Attribute[?(@.value.unknown())]', json: data })).rejects.toThrow();
  });

  it('reports a timeout as a functional error and recovers on a fresh worker', async () => {
    const originalTimeout = conf.get('json_path:timeout');
    const postMessageSpy = vi.spyOn(Worker.prototype, 'postMessage');
    // A large document cannot be copied to the worker and filtered within 1ms
    const json = { items: Array.from({ length: 200000 }, (_, i) => ({ type: i % 2 ? 'ip-dst' : 'domain', value: `${i}` })) };
    conf.set('json_path:timeout', 1);
    try {
      await expect(queryJsonPath({ path: '$.items[?(@.type == \'ip-dst\')].value', json })).rejects.toMatchObject({
        message: 'JSONPath evaluation timeout after 1ms',
        extensions: { code: 'FUNCTIONAL_ERROR' },
      });
    } finally {
      conf.set('json_path:timeout', originalTimeout);
    }
    expect(postMessageSpy).toHaveBeenCalled();
    postMessageSpy.mockRestore();
    // The timed-out worker was discarded, the next query runs on a fresh one
    expect(await queryJsonPath({ path: '$.Event.Attribute[?(@.type == \'domain\')].value', json: data, wrap: false })).toEqual(['filigran.io']);
  });
});
