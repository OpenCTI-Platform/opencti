import { renderHook } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import useConfigPresetDefaultNote from './useConfigPresetDefaultNote';

vi.mock('../../../../../components/i18n', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../components/i18n')>()),
  useFormatter: () => ({ t_i18n: (value: string) => value }),
}));

const BECOMES_TEMPLATE = 'Becomes the default FINTEL template of its entity type.';
const KEPT_TEMPLATE = 'The entity type keeps its current default FINTEL template.';

describe('useConfigPresetDefaultNote', () => {
  const { result } = renderHook(() => useConfigPresetDefaultNote());
  const noteOf = result.current;
  const defaultItem = { isDefault: true, exists: false };
  const imported = { imported: true, hasChoice: false };

  it('says that a default item that does not exist becomes the default, whatever its mode: a copy of it is the item itself', () => {
    expect(noteOf('fintelTemplates', defaultItem, { ...imported, mode: 'COPY' })).toEqual({ kind: 'becomes', text: BECOMES_TEMPLATE });
    expect(noteOf('fintelTemplates', defaultItem, { ...imported, mode: 'OVERWRITE' })).toEqual({ kind: 'becomes', text: BECOMES_TEMPLATE });
    expect(noteOf('fintelTemplates', defaultItem, { ...imported, mode: undefined })).toEqual({ kind: 'becomes', text: BECOMES_TEMPLATE });
    expect(noteOf('fintelDesigns', defaultItem, { ...imported, mode: 'COPY' })).toEqual({ kind: 'becomes', text: 'Becomes the default fintel design of the platform.' });
  });

  it('says that a default item that exists becomes the default when it is overwritten, and that a copy of it keeps the current default', () => {
    const existing = { isDefault: true, exists: true };
    expect(noteOf('fintelTemplates', existing, { imported: true, hasChoice: true, mode: 'OVERWRITE' })).toEqual({ kind: 'becomes', text: BECOMES_TEMPLATE });
    expect(noteOf('fintelTemplates', existing, { imported: true, hasChoice: true, mode: 'COPY' })).toEqual({ kind: 'kept', text: KEPT_TEMPLATE });
    expect(noteOf('branding', existing, { imported: true, hasChoice: true, mode: 'COPY' })).toEqual({ kind: 'kept', text: 'The platform keeps its current default theme.' });
  });

  it('says nothing for an item that is not the default, is not imported, or is of a type whose default the import does not change', () => {
    expect(noteOf('fintelTemplates', { isDefault: false, exists: false }, { ...imported, mode: 'COPY' })).toBeUndefined();
    expect(noteOf('fintelTemplates', defaultItem, { imported: false, hasChoice: false, mode: 'COPY' })).toBeUndefined();
    // The default theme is the one the platform points to: importing it does not make it the default
    expect(noteOf('branding', defaultItem, { ...imported, mode: 'OVERWRITE' })).toBeUndefined();
  });
});
