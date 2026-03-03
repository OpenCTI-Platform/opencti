import { describe, expect, test } from 'vitest';
import convertCustomViewToStix from '../../../../src/modules/customView/customView-converter';
import { ENTITY_TYPE_CUSTOM_VIEW, type StoreEntityCustomView } from '../../../../src/modules/customView/customView-types';
import { toB64 } from '../../../../src/utils/base64';

describe('customView module STIX converter', () => {
  test('converts module-specific properties', () => {
    const customView = {
      entity_type: ENTITY_TYPE_CUSTOM_VIEW,
      name: 'My Custom View',
      description: 'My great custom view description',
      manifest: toB64({
        widgets: [{
          id: 'widget-id',
          layout: {
            x: 0,
            y: 100,
          },
        }],
      }) ?? '',
      restricted_members: [],
    } satisfies Partial<StoreEntityCustomView>;
    const stixCustomView = convertCustomViewToStix(customView as unknown as StoreEntityCustomView);
    expect(stixCustomView).toMatchObject({
      name: customView.name,
      description: customView.description,
      manifest: customView.manifest,
    });
  });
});
