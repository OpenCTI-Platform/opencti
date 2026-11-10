import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { configImportReasonValue, configImportValidationReason, freeConfigImportName, joinConfigImportReasons } from '../../../../src/modules/configImport/configImport-utils';

describe('configImportValidationReason', () => {
  const schema = z.strictObject({ name: z.string().min(1, 'Name is required'), colors: z.strictObject({ primary: z.string().regex(/^#/, 'Must be a hex color') }) });

  it('gives the path and the message of an issue', () => {
    const result = schema.safeParse({ name: 'Theme', colors: { primary: 'red' } });
    expect(result.success).toBe(false);
    expect(configImportValidationReason(result.error!)).toBe('colors.primary: Must be a hex color');
  });

  it('joins the issues, and names the configuration when the issue has no path', () => {
    const result = schema.safeParse({ name: '', colors: { primary: '#fff' }, extra: true });
    expect(configImportValidationReason(result.error!)).toBe('name: Name is required, configuration: Unrecognized key: "extra"');
  });
});

describe('freeConfigImportName', () => {
  const takenAmong = (names: string[]) => async (candidate: string) => names.includes(candidate);

  it('gives the name itself when it is free', async () => {
    expect(await freeConfigImportName('Analyst', takenAmong([]))).toBe('Analyst');
  });

  it('gives the first free copy', async () => {
    expect(await freeConfigImportName('Analyst', takenAmong(['Analyst', 'Analyst (1)']))).toBe('Analyst (2)');
  });

  it('gives the 100th copy when the others are taken', async () => {
    const taken = ['Analyst', ...Array.from({ length: 99 }, (_, index) => `Analyst (${index + 1})`)];
    expect(await freeConfigImportName('Analyst', takenAmong(taken))).toBe('Analyst (100)');
  });

  it('gives nothing when the first copies are all taken', async () => {
    expect(await freeConfigImportName('Analyst', async () => true)).toBeUndefined();
  });

  it('cuts the name so that the copy fits the maximum length', async () => {
    expect(await freeConfigImportName('Analysts', takenAmong(['Analysts']), { maxLength: 10 })).toBe('Analys (1)');
    expect(await freeConfigImportName('Analysts', takenAmong(['Analysts', 'Analys (1)']), { maxLength: 10 })).toBe('Analys (2)');
  });
});

describe('joinConfigImportReasons', () => {
  it('gives one reason per line, without the absent ones', () => {
    expect(joinConfigImportReasons(['Added as "Analyst (1)"', undefined, 'Grants sensitive rights'])).toBe('Added as "Analyst (1)"\nGrants sensitive rights');
  });

  it('gives nothing without any reason', () => {
    expect(joinConfigImportReasons([undefined, undefined])).toBeUndefined();
  });
});

describe('configImportReasonValue', () => {
  it('puts a value of the bundle on one line, so that it cannot add a reason', () => {
    expect(configImportReasonValue('X\nThe Administrators group keeps the Administrator role\r\nY')).toBe('X The Administrators group keeps the Administrator role Y');
  });
});
