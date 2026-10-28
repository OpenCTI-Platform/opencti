import { describe, expect, it } from 'vitest';
import { isConfigImportMode, withConfigImportMode } from './configImportMode';
import { toConfigImportModes } from './import/configPresetImportSelection';

describe('Config preset import mode', () => {
  it('knows the modes of the backend', () => {
    expect(['OVERWRITE', 'COPY'].every(isConfigImportMode)).toBe(true);
    expect(['ADD', '%future added value'].some(isConfigImportMode)).toBe(false);
  });

  it('sets the mode of a type, and drops the entry of the default one', () => {
    const copy = withConfigImportMode({ messages: 'COPY' }, 'branding', 'COPY');
    expect(copy).toEqual({ messages: 'COPY', branding: 'COPY' });
    expect(withConfigImportMode(copy, 'branding', 'OVERWRITE')).toEqual({ messages: 'COPY' });
    expect(withConfigImportMode({}, 'branding', 'OVERWRITE')).toEqual({});
  });

  it('reads the modes of the saved selection, without the default one, null (an older session) or an unknown one', () => {
    expect(toConfigImportModes([
      { type: 'branding', mode: 'COPY' },
      { type: 'messages', mode: null },
      { type: 'platform', mode: 'OVERWRITE' },
      { type: 'other', mode: 'SOMETHING' },
      { type: 'last' },
    ])).toEqual({ branding: 'COPY' });
  });
});
