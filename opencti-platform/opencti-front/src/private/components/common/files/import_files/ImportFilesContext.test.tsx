import { describe, expect, it } from 'vitest';
import { getInitialImportMode } from './ImportFilesContext';

describe('getInitialImportMode', () => {
  it('keeps the requested mode when the user can select the import mode', () => {
    expect(getInitialImportMode(true, false, { importMode: 'manual' })).toBe('manual');
  });

  it('opens the forms for a form-only user in the global import dialog', () => {
    expect(getInitialImportMode(false, true, {})).toBe('form');
  });

  it('opens the file uploader, not the forms, for a form-only user when opened for an entity', () => {
    expect(getInitialImportMode(false, true, { entityId: 'entity-id' })).toBe('auto');
  });

  it('does not open the forms for a form-only user when opened with pre-filled content', () => {
    expect(getInitialImportMode(false, true, { activeStep: 1, importMode: 'manual', initialFreeTextContent: 'a\nb' })).toBe('auto');
  });

  it('imports automatically for a user without the right to select the import mode', () => {
    expect(getInitialImportMode(false, false, {})).toBe('auto');
    expect(getInitialImportMode(false, false, { entityId: 'entity-id' })).toBe('auto');
  });
});
