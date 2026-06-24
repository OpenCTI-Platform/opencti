import { describe, expect, test } from 'vitest';
import convertCustomViewToStix from '../../../../src/modules/customView/customView-converter';
import { ENTITY_TYPE_CUSTOM_VIEW, type StoreEntityCustomView } from '../../../../src/modules/customView/customView-types';
import { toB64 } from '../../../../src/utils/base64';
import { computeCustomViewPath } from '../../../../src/modules/customView/customView-domain';

type StoreEntityCustomViewForTest = Required<Pick<
  StoreEntityCustomView,
  | 'id'
  | 'entity_type'
  | 'name'
  | 'description'
  | 'slug'
  | 'manifest'
  | 'target_entity_type'
  | 'enabled'
  | 'default'
>>;

describe('customView module STIX converter', () => {
  test('converts module-specific properties', () => {
    const customView: StoreEntityCustomViewForTest = {
      id: '4716b259-5856-4d8a-888b-cb2f8bbe52a3',
      entity_type: ENTITY_TYPE_CUSTOM_VIEW,
      name: 'My Great Custom View',
      description: 'My great custom view description',
      slug: 'great-custom-view',
      manifest: toB64({
        widgets: [{
          id: 'widget-id',
          layout: {
            x: 0,
            y: 100,
          },
        }],
      }) ?? '',
      target_entity_type: 'Intrusion-Set',
      enabled: true,
      default: true,
    };
    const stixCustomView = convertCustomViewToStix(customView as unknown as StoreEntityCustomView);
    expect(stixCustomView).toMatchObject({
      name: customView.name,
      description: customView.description,
      slug: 'great-custom-view',
      manifest: customView.manifest,
      target_entity_type: customView.target_entity_type,
      path: computeCustomViewPath(customView as StoreEntityCustomView),
      enabled: true,
      default: true,
    });
  });
});
