import { describe, expect, it, vi } from 'vitest';
import { checkStandardId } from '../../../../src/modules/configPreset/registry/common-configPreset-registry';
import type { ConfigPresetBundleItem } from '../../../../src/modules/configPreset/import/configPreset-import-types';

const item = { type: 'things', id: 'thing--abc', path: 'taxonomy/things/thing--abc.json', configuration: {} } as ConfigPresetBundleItem;
const label = { label: 'Thing', translatable: false };
const reason = 'The standard id does not match';

describe('checkStandardId', () => {
  it('reports nothing when the id of the item is the standard id of its values', () => {
    const getStandardId = vi.fn(() => 'thing--abc');
    expect(checkStandardId(item, label, ['first', 'second'], getStandardId, reason)).toBeUndefined();
    expect(getStandardId).toHaveBeenCalledWith(['first', 'second']);
  });

  it('fails the item whose id is another standard id', () => {
    expect(checkStandardId(item, label, ['first'], () => 'thing--other', reason)).toEqual({
      label: 'Thing',
      translatable: false,
      exists: false,
      conflict: false,
      status: 'failed',
      reason,
    });
  });

  it.each([
    ['blank', ['first', '  ']],
    ['empty', ['']],
    ['missing', [undefined]],
    ['not a string', [12]],
  ])('does not derive the standard id of a %s value, the module refuses the item', (_name, values) => {
    const getStandardId = vi.fn(() => {
      throw new Error('Missing required elements');
    });
    expect(checkStandardId(item, label, values, getStandardId, reason)).toBeUndefined();
    expect(getStandardId).not.toHaveBeenCalled();
  });
});
