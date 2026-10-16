import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQueryHelper';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../../../src/modules/case/case-incident/case-incident-types';
import type { OverviewLayoutCustomization } from '../../../src/modules/entitySetting/entitySetting-types';
import { schemaOverviewLayoutCustomization } from '../../../src/schema/schema-overviewLayoutCustomization';

const READ_QUERY = gql`
  query entitySettingOverviewLayout($targetType: String!) {
    entitySettingByType(targetType: $targetType) {
      id
      overview_layout_customization {
        key
        width
        label
      }
      defaultOverviewLayoutCustomization {
        key
        width
        label
      }
    }
  }
`;

const UPDATE_QUERY = gql`
  mutation entitySettingOverviewLayoutEdit($ids: [ID!]!, $input: [EditInput!]!) {
    entitySettingsFieldPatch(ids: $ids, input: $input) {
      id
      overview_layout_customization {
        key
        width
        label
      }
    }
  }
`;

const TIMELINE_WIDGET = { key: 'timeline', width: 6, label: 'Timeline' };

// The layout of an incident response saved by an administrator before the timeline was a widget
const LEGACY_LAYOUT: OverviewLayoutCustomization[] = [
  { key: 'details', width: 12, label: 'Entity details' },
  { key: 'basicInformation', width: 12, label: 'Basic information' },
  { key: 'task', width: 6, label: 'Tasks' },
  { key: 'originOfTheCase', width: 6, label: 'Origin of the case' },
  { key: 'observables', width: 6, label: 'Observables' },
  { key: 'relatedEntities', width: 6, label: 'Related entities' },
  { key: 'mostRecentHistory', width: 6, label: 'Most recent history' },
  { key: 'externalReferences', width: 6, label: 'External references' },
  { key: 'notes', width: 12, label: 'Notes about this entity' },
];

describe('EntitySetting resolver - overview layout of the incident response timeline', () => {
  let entitySettingId: string;
  const readLayout = async () => {
    const result = await queryAsAdmin({ query: READ_QUERY, variables: { targetType: ENTITY_TYPE_CONTAINER_CASE_INCIDENT } });
    return result.data?.entitySettingByType.overview_layout_customization as OverviewLayoutCustomization[];
  };
  const storeLayout = async (layout: OverviewLayoutCustomization[]) => {
    const result = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { ids: [entitySettingId], input: { key: 'overview_layout_customization', value: layout } },
    });
    return result.data?.entitySettingsFieldPatch?.[0]?.overview_layout_customization as OverviewLayoutCustomization[];
  };

  it('should list the timeline right after the basic information in the default layout', async () => {
    const result = await queryAsAdmin({ query: READ_QUERY, variables: { targetType: ENTITY_TYPE_CONTAINER_CASE_INCIDENT } });
    entitySettingId = result.data?.entitySettingByType.id;
    expect(entitySettingId).toBeTruthy();
    const layout = result.data?.entitySettingByType.overview_layout_customization;
    expect(layout).toEqual(schemaOverviewLayoutCustomization.get(ENTITY_TYPE_CONTAINER_CASE_INCIDENT));
    const basicInformation = layout.findIndex(({ key }: OverviewLayoutCustomization) => key === 'basicInformation');
    expect(layout[basicInformation + 1]).toEqual(TIMELINE_WIDGET);
  });

  it('should add the timeline after the basic information to a layout stored before it existed', async () => {
    const merged = [...LEGACY_LAYOUT.slice(0, 2), TIMELINE_WIDGET, ...LEGACY_LAYOUT.slice(2)];
    expect(await storeLayout(LEGACY_LAYOUT)).toEqual(merged);
    expect(await readLayout()).toEqual(merged);
  });

  it('should keep the timeline where it was moved and resized', async () => {
    const moved = [{ ...TIMELINE_WIDGET, width: 12 }, ...LEGACY_LAYOUT];
    expect(await storeLayout(moved)).toEqual(moved);
    expect(await readLayout()).toEqual(moved);
  });

  it('should keep a hidden timeline hidden', async () => {
    const hidden = [...LEGACY_LAYOUT, { ...TIMELINE_WIDGET, width: 0 }];
    expect(await storeLayout(hidden)).toEqual(hidden);
    expect(await readLayout()).toEqual(hidden);
  });

  it('should expose the default layout next to a customized one', async () => {
    const result = await queryAsAdmin({ query: READ_QUERY, variables: { targetType: ENTITY_TYPE_CONTAINER_CASE_INCIDENT } });
    expect(result.data?.entitySettingByType.defaultOverviewLayoutCustomization).toEqual(schemaOverviewLayoutCustomization.get(ENTITY_TYPE_CONTAINER_CASE_INCIDENT));
  });

  it('should reset to the default layout', async () => {
    expect(await storeLayout([])).toEqual(schemaOverviewLayoutCustomization.get(ENTITY_TYPE_CONTAINER_CASE_INCIDENT));
  });
});
