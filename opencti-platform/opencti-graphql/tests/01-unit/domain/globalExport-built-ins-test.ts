import { describe, expect, it, vi } from 'vitest';
import { isFeatureEnabled } from '../../../src/config/conf';
import { withBuiltInExportId } from '../../../src/modules/globalExport/globalExport-built-ins';
import { generateBuiltInExportId } from '../../../src/schema/identifier';

vi.mock('../../../src/config/conf', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  isFeatureEnabled: vi.fn(() => true),
}));

describe('Built-in export_id on creation', () => {
  it('should add the export_id of a built-in element when GLOBAL_EXPORT_BUNDLE is enabled', () => {
    vi.mocked(isFeatureEnabled).mockReturnValue(true);
    expect(withBuiltInExportId({ name: 'Administrators' }, 'Group')).toEqual({
      name: 'Administrators',
      export_id: generateBuiltInExportId('Group', { name: 'Administrators' }),
    });
    expect(isFeatureEnabled).toHaveBeenCalledWith('GLOBAL_EXPORT_BUNDLE');
  });

  it('should return the input unchanged when GLOBAL_EXPORT_BUNDLE is disabled', () => {
    // The export_id attribute is not registered: storing it would be rejected by the strict mapping
    vi.mocked(isFeatureEnabled).mockReturnValue(false);
    const input = { name: 'Administrators' };
    expect(withBuiltInExportId(input, 'Group')).toBe(input);
  });

  it('should not add an export_id to an element that is not built-in or whose type has none', () => {
    vi.mocked(isFeatureEnabled).mockReturnValue(true);
    const userTheme = { name: 'ACME', built_in: false };
    expect(withBuiltInExportId(userTheme, 'Theme')).toBe(userTheme);
    const capability = { name: 'BYPASS' };
    expect(withBuiltInExportId(capability, 'Capability')).toBe(capability);
  });
});
