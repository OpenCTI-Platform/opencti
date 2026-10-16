import { describe, expect, it } from 'vitest';
import type { FilterDefinition } from '../../../../src/domain/filterKeysSchema';
import { restrictTimelineAnchorFilterKeys } from '../../../../src/modules/timeline/timeline-headline-dates';
import { ENTITY_TYPE_INCIDENT } from '../../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../../../../src/modules/case/case-incident/case-incident-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../../../src/modules/case/case-rfi/case-rfi-types';

const definition = (filterKey: string, subEntityTypes: string[]): FilterDefinition => ({
  filterKey,
  type: 'date',
  label: filterKey,
  multiple: false,
  subEntityTypes,
  elementsForFilterValuesSearch: [],
});

const schemaOf = (entries: Record<string, string[]>) => new Map(Object.entries(entries).map(([type, keys]) => [
  type,
  new Map(keys.map((key) => [key, definition(key, type === 'Case' ? [ENTITY_TYPE_CONTAINER_CASE_INCIDENT, ENTITY_TYPE_CONTAINER_CASE_RFI] : [type])])),
]));

describe('Timeline headline dates', () => {
  it('should keep only the anchor filters of the headline dates of each timeline type', () => {
    const schema = schemaOf({
      [ENTITY_TYPE_CONTAINER_CASE_INCIDENT]: ['name', 'x_opencti_timeline_anchors.containment', 'x_opencti_timeline_anchors.eradication'],
      [ENTITY_TYPE_INCIDENT]: ['name', 'x_opencti_timeline_anchors.containment', 'x_opencti_timeline_anchors.eradication'],
      Case: ['name', 'x_opencti_timeline_anchors.containment', 'x_opencti_timeline_anchors.eradication'],
    });
    restrictTimelineAnchorFilterKeys(schema, {
      [ENTITY_TYPE_CONTAINER_CASE_INCIDENT]: ['containment', 'eradication', 'closure'],
      [ENTITY_TYPE_INCIDENT]: ['containment', 'closure'],
      [ENTITY_TYPE_CONTAINER_CASE_RFI]: ['containment', 'closure'],
    });
    expect([...(schema.get(ENTITY_TYPE_CONTAINER_CASE_INCIDENT)?.keys() ?? [])])
      .toEqual(['name', 'x_opencti_timeline_anchors.containment', 'x_opencti_timeline_anchors.eradication']);
    // A date the type does not show is no filter of its lists
    expect([...(schema.get(ENTITY_TYPE_INCIDENT)?.keys() ?? [])]).toEqual(['name', 'x_opencti_timeline_anchors.containment']);
    // On a parent type, the filter names only the types showing the date
    expect(schema.get('Case')?.get('x_opencti_timeline_anchors.containment')?.subEntityTypes)
      .toEqual([ENTITY_TYPE_CONTAINER_CASE_INCIDENT, ENTITY_TYPE_CONTAINER_CASE_RFI]);
    expect(schema.get('Case')?.get('x_opencti_timeline_anchors.eradication')?.subEntityTypes).toEqual([ENTITY_TYPE_CONTAINER_CASE_INCIDENT]);
    expect(schema.get('Case')?.get('name')?.subEntityTypes).toEqual([ENTITY_TYPE_CONTAINER_CASE_INCIDENT, ENTITY_TYPE_CONTAINER_CASE_RFI]);
  });

  it('should drop an anchor filter no type of the list shows', () => {
    const schema = schemaOf({ Case: ['x_opencti_timeline_anchors.recovery'] });
    restrictTimelineAnchorFilterKeys(schema, {
      [ENTITY_TYPE_CONTAINER_CASE_INCIDENT]: ['containment'],
      [ENTITY_TYPE_CONTAINER_CASE_RFI]: ['closure'],
    });
    expect(schema.get('Case')?.has('x_opencti_timeline_anchors.recovery')).toBe(false);
  });
});
