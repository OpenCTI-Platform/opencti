import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { configImportValidationReason } from '../../../../src/modules/configImport/configImport-utils';

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
