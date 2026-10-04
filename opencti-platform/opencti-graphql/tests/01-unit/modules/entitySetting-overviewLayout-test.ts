import { describe, expect, it } from 'vitest';
import '../../../src/modules/case/case-incident/case-incident';
import '../../../src/modules/case/case-rfi/case-rfi';
import '../../../src/modules/case/case-rft/case-rft';
import '../../../src/modules/incident/incident';
import { getDefaultOverviewLayoutCustomization, getOverviewLayoutCustomization } from '../../../src/modules/entitySetting/entitySetting-domain';
import { mergeOverviewLayoutCustomization } from '../../../src/modules/entitySetting/entitySetting-utils';
import type { BasicStoreEntityEntitySetting, OverviewLayoutCustomization } from '../../../src/modules/entitySetting/entitySetting-types';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../../../src/modules/case/case-incident/case-incident-types';
import { TIMELINE_CONTAINER_TYPES } from '../../../src/modules/timeline/timeline-types';
import { schemaOverviewLayoutCustomization } from '../../../src/schema/schema-overviewLayoutCustomization';

const TIMELINE_WIDGET = { key: 'timeline', width: 6, label: 'Timeline' };

// The overview grid has 12 columns: a widget wider than what remains of a row starts the next row and leaves a gap
const GRID_COLUMNS = 12;
const rowGaps = (layout: OverviewLayoutCustomization[]) => {
  const gaps: string[] = [];
  let filled = 0;
  layout.forEach(({ key, width }) => {
    if (filled + width > GRID_COLUMNS) {
      gaps.push(`before ${key}`);
      filled = 0;
    }
    filled = (filled + width) % GRID_COLUMNS;
  });
  if (filled > 0) {
    gaps.push('at the end');
  }
  return gaps;
};

const entitySetting = (targetType: string, layout?: OverviewLayoutCustomization[]) => {
  return { target_type: targetType, overview_layout_customization: layout } as BasicStoreEntityEntitySetting;
};

// The layout of an incident response saved by an administrator before the timeline was a widget
const LEGACY_CASE_INCIDENT_LAYOUT: OverviewLayoutCustomization[] = [
  { key: 'notes', width: 12, label: 'Notes about this entity' },
  { key: 'details', width: 12, label: 'Entity details' },
  { key: 'basicInformation', width: 6, label: 'Basic information' },
  { key: 'task', width: 6, label: 'Tasks' },
  { key: 'originOfTheCase', width: 6, label: 'Origin of the case' },
  { key: 'observables', width: 6, label: 'Observables' },
  { key: 'relatedEntities', width: 6, label: 'Related entities' },
  { key: 'externalReferences', width: 6, label: 'External references' },
  { key: 'mostRecentHistory', width: 6, label: 'Most recent history' },
];

describe('Overview layout of the timeline containers', () => {
  it('declares the timeline as a half-width widget right after the basic information of every timeline container type', () => {
    expect(TIMELINE_CONTAINER_TYPES).toHaveLength(4);
    TIMELINE_CONTAINER_TYPES.forEach((type) => {
      const defaultLayout = schemaOverviewLayoutCustomization.get(type) ?? [];
      const basicInformation = defaultLayout.findIndex(({ key }) => key === 'basicInformation');
      expect(basicInformation).toBeGreaterThan(0);
      expect(defaultLayout[basicInformation + 1]).toEqual(TIMELINE_WIDGET);
      expect(defaultLayout.filter(({ key }) => key === TIMELINE_WIDGET.key)).toHaveLength(1);
    });
  });

  it('fills every row of the default layout of every timeline container type, without a widget alone on half of a row', () => {
    TIMELINE_CONTAINER_TYPES.forEach((type) => {
      expect(rowGaps(schemaOverviewLayoutCustomization.get(type) ?? []), type).toEqual([]);
    });
  });

  it('returns the default layout, timeline after the basic information, when no layout is stored', () => {
    const defaultLayout = schemaOverviewLayoutCustomization.get(ENTITY_TYPE_CONTAINER_CASE_INCIDENT);
    expect(getOverviewLayoutCustomization(entitySetting(ENTITY_TYPE_CONTAINER_CASE_INCIDENT))).toEqual(defaultLayout);
    expect(getOverviewLayoutCustomization(entitySetting(ENTITY_TYPE_CONTAINER_CASE_INCIDENT, []))).toEqual(defaultLayout);
    expect(getOverviewLayoutCustomization(entitySetting(ENTITY_TYPE_CONTAINER_CASE_INCIDENT))?.map(({ key }) => key)).toEqual([
      'details',
      'basicInformation',
      'timeline',
      'task',
      'originOfTheCase',
      'observables',
      'relatedEntities',
      'externalReferences',
      'mostRecentHistory',
      'notes',
    ]);
  });

  it('adds the timeline after the basic information to a layout stored before it existed, keeping the stored order and widths', () => {
    const layout = getOverviewLayoutCustomization(entitySetting(ENTITY_TYPE_CONTAINER_CASE_INCIDENT, LEGACY_CASE_INCIDENT_LAYOUT));
    expect(layout).toEqual([...LEGACY_CASE_INCIDENT_LAYOUT.slice(0, 3), TIMELINE_WIDGET, ...LEGACY_CASE_INCIDENT_LAYOUT.slice(3)]);
  });

  it('keeps the timeline where the administrator moved or resized it', () => {
    const stored = [{ ...TIMELINE_WIDGET, width: 12 }, ...LEGACY_CASE_INCIDENT_LAYOUT];
    expect(getOverviewLayoutCustomization(entitySetting(ENTITY_TYPE_CONTAINER_CASE_INCIDENT, stored))).toEqual(stored);
  });

  it('keeps a hidden timeline hidden instead of adding it again', () => {
    const stored = [...LEGACY_CASE_INCIDENT_LAYOUT, { ...TIMELINE_WIDGET, width: 0 }];
    const layout = getOverviewLayoutCustomization(entitySetting(ENTITY_TYPE_CONTAINER_CASE_INCIDENT, stored));
    expect(layout).toEqual(stored);
    expect(layout?.filter(({ key }) => key === TIMELINE_WIDGET.key)).toEqual([{ ...TIMELINE_WIDGET, width: 0 }]);
  });

  it('exposes the default layout whatever the stored layout', () => {
    const hidden = [...LEGACY_CASE_INCIDENT_LAYOUT, { ...TIMELINE_WIDGET, width: 0 }];
    expect(getDefaultOverviewLayoutCustomization(entitySetting(ENTITY_TYPE_CONTAINER_CASE_INCIDENT, hidden)))
      .toEqual(schemaOverviewLayoutCustomization.get(ENTITY_TYPE_CONTAINER_CASE_INCIDENT));
  });

  it('returns a stored layout as is for a type without default layout', () => {
    const stored = [{ key: 'details', width: 12, label: 'Entity details' }];
    expect(getOverviewLayoutCustomization(entitySetting('Unknown-Type', stored))).toEqual(stored);
  });
});

describe('Merge of a stored overview layout with the default layout', () => {
  const defaults = [
    { key: 'a', width: 6, label: 'A' },
    { key: 'b', width: 6, label: 'B' },
    { key: 'c', width: 6, label: 'C' },
    { key: 'd', width: 12, label: 'D' },
  ];

  it('inserts a missing widget right after the closest widget preceding it in the default layout', () => {
    const stored = [{ key: 'd', width: 6, label: 'D' }, { key: 'a', width: 12, label: 'A' }, { key: 'c', width: 6, label: 'C' }];
    expect(mergeOverviewLayoutCustomization(stored, defaults).map(({ key }) => key)).toEqual(['d', 'a', 'b', 'c']);
  });

  it('inserts consecutive missing widgets in their default order', () => {
    const stored = [{ key: 'd', width: 12, label: 'D' }, { key: 'a', width: 6, label: 'A' }];
    expect(mergeOverviewLayoutCustomization(stored, defaults).map(({ key }) => key)).toEqual(['d', 'a', 'b', 'c']);
  });

  it('inserts first a missing widget that no default widget precedes', () => {
    const stored = [{ key: 'c', width: 6, label: 'C' }, { key: 'b', width: 6, label: 'B' }, { key: 'd', width: 12, label: 'D' }];
    expect(mergeOverviewLayoutCustomization(stored, defaults).map(({ key }) => key)).toEqual(['a', 'c', 'b', 'd']);
  });

  it('keeps the stored widgets unknown to the default layout and never mutates its inputs', () => {
    const stored = [{ key: 'custom', width: 6, label: 'Custom' }, { key: 'b', width: 12, label: 'B' }];
    const storedCopy = structuredClone(stored);
    const merged = mergeOverviewLayoutCustomization(stored, defaults);
    expect(merged).toEqual([
      { key: 'a', width: 6, label: 'A' },
      { key: 'custom', width: 6, label: 'Custom' },
      { key: 'b', width: 12, label: 'B' },
      { key: 'c', width: 6, label: 'C' },
      { key: 'd', width: 12, label: 'D' },
    ]);
    expect(stored).toEqual(storedCopy);
    expect(defaults).toHaveLength(4);
  });
});
