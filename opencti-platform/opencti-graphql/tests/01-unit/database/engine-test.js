import { describe, expect, it, vi } from 'vitest';
import { buildLocalMustFilter, isTransitoryError, prepareElementForIndexing } from '../../../src/database/engine';
import * as engineConfig from '../../../src/database/engine-config';

describe('prepareElementForIndexing testing', () => {
  it('should base trim applied', async () => {
    const element = await prepareElementForIndexing({ name: '  test' });
    expect(element.name).toBe('test');
  });
  it('should inner trim applied', async () => {
    const element = await prepareElementForIndexing({ num: 10, data: { test: '  spacing   ' } });
    expect(element.num).toBe(10);
    expect(element.data.test).toBe('spacing');
  });
  it('should array trim applied', async () => {
    const element = await prepareElementForIndexing({ test: [20, '  trim01  ', '  trim 02    '] });
    expect(element.test).toEqual([20, 'trim01', 'trim 02']);
  });
  it('should inner array trim applied', async () => {
    const element = await prepareElementForIndexing({ test: { values: [20, '  trim01  ', '  trim 02    '] } });
    expect(element.test.values).toEqual([20, 'trim01', 'trim 02']);
  });
  it('should do nothing with date value', async () => {
    const now = new Date();
    const element = await prepareElementForIndexing({ date: now });
    expect(element.date).toEqual(now);
  });
});

describe('buildLocalMustFilter testing', () => {
  it('should buildLocalMustFilter with script be refused by default', () => {
    const scriptFilter = {
      key: ['name'],
      values: [
        'doc.containsKey(\'name.keyword\')',
      ],
      operator: 'script',
    };

    expect(() => buildLocalMustFilter(scriptFilter)).toThrow(/Filter script is not allowed/);
  });

  it('should buildLocalMustFilter with internal_script should work', () => {
    const scriptFilter = {
      key: ['name'],
      values: [
        'doc.containsKey(\'name.keyword\')',
      ],
      operator: 'internal_script',
    };

    const result = buildLocalMustFilter(scriptFilter);

    expect(result).toStrictEqual({
      bool: {
        minimum_should_match: 1,
        should: [
          {
            script: {
              script: "doc.containsKey('name.keyword')",
            },
          },
        ],
      },
    });
  });

  it('buildLocalMustFilter with script should work when enabled', () => {
    vi.spyOn(engineConfig, 'isEsScriptFilterEnabled').mockResolvedValue(true);
    const scriptFilter = {
      key: ['name'],
      values: [
        'doc.containsKey(\'name.keyword\')',
      ],
      operator: 'script',
    };

    const result = buildLocalMustFilter(scriptFilter);

    expect(result).toStrictEqual({
      bool: {
        minimum_should_match: 1,
        should: [
          {
            script: {
              script: "doc.containsKey('name.keyword')",
            },
          },
        ],
      },
    });
  });

  it('should buildLocalMustFilter with contact_information emit a single terms clause for multiple values', () => {
    const emails = ['user@example.com', 'user2@example.com', 'user3@example.com'];
    const filter = {
      key: ['contact_information'],
      values: emails,
      operator: 'eq',
    };

    const result = buildLocalMustFilter(filter);

    expect(result).toStrictEqual({
      bool: {
        minimum_should_match: 1,
        should: [
          {
            terms: { 'contact_information.keyword': emails },
          },
        ],
      },
    });
  });
});

describe('isTransitoryError testing', () => {
  // ── Status code branch ─────────────────────────────────────────────────────

  it('should return true for statusCode 429 on root error', () => {
    expect(isTransitoryError({ statusCode: 429 })).toBe(true);
  });

  it('should return true for statusCode 503 on root error', () => {
    expect(isTransitoryError({ statusCode: 503 })).toBe(true);
  });

  it('should return true for statusCode 429 via meta.statusCode', () => {
    expect(isTransitoryError({ meta: { statusCode: 429 } })).toBe(true);
  });

  it('should return true for statusCode 503 via meta.statusCode', () => {
    expect(isTransitoryError({ meta: { statusCode: 503 } })).toBe(true);
  });

  it('should return true for statusCode 429 via status field', () => {
    expect(isTransitoryError({ status: 429 })).toBe(true);
  });

  it('should return true for statusCode 503 via status field', () => {
    expect(isTransitoryError({ status: 503 })).toBe(true);
  });

  it('should return true for statusCode 429 via cause.statusCode', () => {
    expect(isTransitoryError({ cause: { statusCode: 429 } })).toBe(true);
  });

  it('should return true for statusCode 503 via cause.meta.statusCode', () => {
    expect(isTransitoryError({ cause: { meta: { statusCode: 503 } } })).toBe(true);
  });

  it('should return true for statusCode 429 via extensions.data.cause.statusCode', () => {
    expect(isTransitoryError({ extensions: { data: { cause: { statusCode: 429 } } } })).toBe(true);
  });

  it('should return true for statusCode 503 via extensions.data.cause.meta.statusCode', () => {
    expect(isTransitoryError({ extensions: { data: { cause: { meta: { statusCode: 503 } } } } })).toBe(true);
  });

  it('should return false for a non-transitory statusCode (e.g. 500)', () => {
    expect(isTransitoryError({ statusCode: 500 })).toBe(false);
  });

  it('should return false for statusCode 200', () => {
    expect(isTransitoryError({ statusCode: 200 })).toBe(false);
  });

  // ── Error code branch ───────────────────────────────────────────────────────

  it('should return true for ECONNRESET via root code', () => {
    expect(isTransitoryError({ code: 'ECONNRESET' })).toBe(true);
  });

  it('should return true for ECONNREFUSED via root code', () => {
    expect(isTransitoryError({ code: 'ECONNREFUSED' })).toBe(true);
  });

  it('should return true for ETIMEDOUT via root code', () => {
    expect(isTransitoryError({ code: 'ETIMEDOUT' })).toBe(true);
  });

  it('should return true for EPIPE via root code', () => {
    expect(isTransitoryError({ code: 'EPIPE' })).toBe(true);
  });

  it('should return true for EAI_AGAIN via root code', () => {
    expect(isTransitoryError({ code: 'EAI_AGAIN' })).toBe(true);
  });

  it('should return true for ECONNRESET via cause.code', () => {
    expect(isTransitoryError({ cause: { code: 'ECONNRESET' } })).toBe(true);
  });

  it('should return true for ETIMEDOUT via originalError.code', () => {
    expect(isTransitoryError({ originalError: { code: 'ETIMEDOUT' } })).toBe(true);
  });

  it('should return true for ECONNREFUSED via extensions.data.cause.code', () => {
    expect(isTransitoryError({ extensions: { data: { cause: { code: 'ECONNREFUSED' } } } })).toBe(true);
  });

  it('should return false for a non-transitory error code', () => {
    expect(isTransitoryError({ code: 'ENOENT' })).toBe(false);
  });

  // ── Text pattern branch – message field ────────────────────────────────────

  it('should return true when root message contains circuit_breaking_exception', () => {
    expect(isTransitoryError({ message: 'circuit_breaking_exception: [parent] Data too large' })).toBe(true);
  });

  it('should return true when root message contains es_rejected_execution', () => {
    expect(isTransitoryError({ message: 'es_rejected_execution: queue capacity reached' })).toBe(true);
  });

  it('should return true when root message contains too_many_requests', () => {
    expect(isTransitoryError({ message: 'too_many_requests' })).toBe(true);
  });

  it('should return true when root message contains service_unavailable', () => {
    expect(isTransitoryError({ message: 'service_unavailable' })).toBe(true);
  });

  it('should return true when pattern is mixed-case (case-insensitive match)', () => {
    expect(isTransitoryError({ message: 'Circuit_Breaking_Exception occurred' })).toBe(true);
  });

  // ── Text pattern branch – nested paths via collectErrorFieldValues ──────────

  it('should return true when cause.message contains circuit_breaking_exception', () => {
    expect(isTransitoryError({ cause: { message: 'circuit_breaking_exception' } })).toBe(true);
  });

  it('should return true when cause.meta.body.error.message contains circuit_breaking_exception', () => {
    expect(isTransitoryError({ cause: { meta: { body: { error: { message: 'circuit_breaking_exception' } } } } })).toBe(true);
  });

  it('should return true when originalError.message contains es_rejected_execution', () => {
    expect(isTransitoryError({ originalError: { message: 'es_rejected_execution' } })).toBe(true);
  });

  it('should return true when meta.body.error.message contains circuit_breaking_exception', () => {
    expect(isTransitoryError({ meta: { body: { error: { message: 'circuit_breaking_exception' } } } })).toBe(true);
  });

  it('should return true when extensions.data.cause.message contains too_many_requests', () => {
    expect(isTransitoryError({ extensions: { data: { cause: { message: 'too_many_requests' } } } })).toBe(true);
  });

  it('should return true when extensions.data.cause.meta.body.error.message contains circuit_breaking_exception', () => {
    expect(isTransitoryError({
      extensions: { data: { cause: { meta: { body: { error: { message: 'circuit_breaking_exception' } } } } } },
    })).toBe(true);
  });

  it('should return true when extensions.exception.message contains service_unavailable', () => {
    expect(isTransitoryError({ extensions: { exception: { message: 'service_unavailable' } } })).toBe(true);
  });

  // ── Text pattern branch – other field names (reason / type / name / stack) ──

  it('should return true when reason field contains circuit_breaking_exception', () => {
    expect(isTransitoryError({ reason: 'circuit_breaking_exception' })).toBe(true);
  });

  it('should return true when type field contains es_rejected_execution', () => {
    expect(isTransitoryError({ type: 'es_rejected_execution' })).toBe(true);
  });

  it('should return true when name field contains too_many_requests', () => {
    expect(isTransitoryError({ name: 'too_many_requests' })).toBe(true);
  });

  it('should return true when stack field contains circuit_breaking_exception', () => {
    expect(isTransitoryError({ stack: 'ResponseError: circuit_breaking_exception\n at something' })).toBe(true);
  });

  // ── Real-world production error shape (from the reported bug) ──────────────

  it('should return true for the real-world circuit_breaking_exception ResponseError shape', () => {
    const error = {
      code: 'UNKNOWN_ERROR',
      message: 'circuit_breaking_exception\n\tRoot causes:\n\t\tcircuit_breaking_exception: [parent] Data too large, data for [<http_request>] would be [6254606938/5.8gb], which is larger than the limit of [6120328396/5.6gb]',
      name: 'ResponseError',
      stack: 'ResponseError: circuit_breaking_exception\n\tRoot causes:\n\t\tcircuit_breaking_exception: [parent] Data too large',
    };
    expect(isTransitoryError(error)).toBe(true);
  });

  // ── False cases ─────────────────────────────────────────────────────────────

  it('should return false for a plain non-transitory error', () => {
    expect(isTransitoryError({ message: 'index_not_found_exception', code: 'ENOENT', statusCode: 404 })).toBe(false);
  });

  it('should return false for null', () => {
    expect(isTransitoryError(null)).toBe(false);
  });

  it('should return false for undefined', () => {
    expect(isTransitoryError(undefined)).toBe(false);
  });

  it('should return false for an empty object', () => {
    expect(isTransitoryError({})).toBe(false);
  });

  it('should return false when text fields are empty strings (not matched)', () => {
    expect(isTransitoryError({ message: '', reason: '', type: '', name: '', stack: '' })).toBe(false);
  });
});
