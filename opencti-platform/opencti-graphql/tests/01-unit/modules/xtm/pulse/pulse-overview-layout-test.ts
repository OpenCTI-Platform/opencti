import { describe, expect, it } from 'vitest';
import '../../../../../src/modules/indicator/indicator';
import '../../../../../src/modules/intrusionSet/intrusionSet';
import '../../../../../src/modules/malware/malware';
import '../../../../../src/modules/tool/tool';
import '../../../../../src/modules/vulnerability/vulnerability';
import '../../../../../src/modules/attackPattern/attackPattern';
import { schemaOverviewLayoutCustomization } from '../../../../../src/schema/schema-overviewLayoutCustomization';
import { mergeOverviewLayoutCustomization } from '../../../../../src/modules/entitySetting/entitySetting-utils';
import { PULSE_SCOPE_ENTITY_TYPES } from '../../../../../src/modules/xtm/pulse/pulse-types';
import { ENTITY_TYPE_INTRUSION_SET } from '../../../../../src/schema/stixDomainObject';
import type { OverviewLayoutCustomization } from '../../../../../src/modules/entitySetting/entitySetting-types';

const THREAT_PULSE_WIDGET = { key: 'threatPulse', width: 6, label: 'Threat Pulse' };

describe('Threat Pulse overview widget', () => {
  it.each(PULSE_SCOPE_ENTITY_TYPES)('is a half width widget right after basic information in the default layout of %s', (entityType) => {
    const layout = schemaOverviewLayoutCustomization.get(entityType) ?? [];
    const keys = layout.map(({ key }) => key);
    expect(keys.indexOf('threatPulse')).toEqual(keys.indexOf('basicInformation') + 1);
    expect(layout.find(({ key }) => key === 'threatPulse')).toEqual(THREAT_PULSE_WIDGET);
  });

  it('joins a layout customized before it existed right after basic information, keeping the customization', () => {
    const storedLayout: OverviewLayoutCustomization[] = [
      { key: 'basicInformation', width: 12, label: 'Basic information' },
      { key: 'details', width: 12, label: 'Entity details' },
      { key: 'notes', width: 12, label: 'Notes about this entity' },
      { key: 'latestCreatedRelationships', width: 6, label: 'Latest created relationships' },
      { key: 'latestContainers', width: 6, label: 'Latest containers' },
      { key: 'externalReferences', width: 6, label: 'External references' },
      { key: 'mostRecentHistory', width: 6, label: 'Most recent history' },
    ];
    const merged = mergeOverviewLayoutCustomization(storedLayout, schemaOverviewLayoutCustomization.get(ENTITY_TYPE_INTRUSION_SET) ?? []);
    expect(merged.map(({ key }) => key)).toEqual([
      'basicInformation',
      'threatPulse',
      'details',
      'notes',
      'latestCreatedRelationships',
      'latestContainers',
      'externalReferences',
      'mostRecentHistory',
    ]);
    expect(merged.find(({ key }) => key === 'threatPulse')).toEqual(THREAT_PULSE_WIDGET);
    expect(merged.filter(({ key }) => key !== 'threatPulse')).toEqual(storedLayout);
  });

  it('keeps a layout that already places the widget as it was saved', () => {
    const storedLayout: OverviewLayoutCustomization[] = [
      { ...THREAT_PULSE_WIDGET, width: 12 },
      ...(schemaOverviewLayoutCustomization.get(ENTITY_TYPE_INTRUSION_SET) ?? []).filter(({ key }) => key !== 'threatPulse'),
    ];
    const merged = mergeOverviewLayoutCustomization(storedLayout, schemaOverviewLayoutCustomization.get(ENTITY_TYPE_INTRUSION_SET) ?? []);
    expect(merged).toEqual(storedLayout);
  });

  it('places a missing first default widget first and a widget after a missing one after its own predecessor', () => {
    const defaultLayout = [{ key: 'a' }, { key: 'b' }, { key: 'c' }];
    expect(mergeOverviewLayoutCustomization([{ key: 'c' }], defaultLayout).map(({ key }) => key)).toEqual(['a', 'b', 'c']);
    expect(mergeOverviewLayoutCustomization([{ key: 'c' }, { key: 'a' }], defaultLayout).map(({ key }) => key)).toEqual(['c', 'a', 'b']);
  });
});
