import { describe, expect, it } from 'vitest';
import { getDataID } from './environment';

describe('getDataID', () => {
  it('keeps a singleton config preset category and its item in separate records', () => {
    expect(getDataID({ id: 'platform' }, 'ConfigPresetExportableType')).not.toEqual(getDataID({ id: 'platform' }, 'ConfigPresetExportableItem'));
  });
});
