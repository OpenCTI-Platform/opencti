import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { getEntitiesListFromCache } from '../../../../src/database/cache';
import {
  isProvenanceTrackedForType,
  isProvenanceTrackingEnabled,
  listProvenanceRelationshipTracking,
  listProvenanceTrackedTypes,
  listProvenanceUntrackedTypesOfSetting,
  parseProvenanceRelationshipTypes,
  parseProvenanceRelationshipTypesStrict,
  PROVENANCE_RECOMMENDED_RELATIONSHIP_TYPES_SETTING,
} from '../../../../src/modules/provenance/provenance-tracking';
import { getOverviewLayoutCustomization, insertSourcesWidget, mergeMissingWidgets } from '../../../../src/modules/entitySetting/entitySetting-domain';
import { creationProceduresBuilder } from '../../../../src/modules/provenance/provenance-upsert';
import { resolveStatisticsTypes } from '../../../../src/modules/provenance/provenance-domain';
import type { BasicStoreEntityEntitySetting } from '../../../../src/modules/entitySetting/entitySetting-types';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/modules/provenance/provenance-config', () => ({
  PROVENANCE_ENABLED: true,
  PROVENANCE_REASSERTION_WINDOW_MS: 24 * 60 * 60 * 1000,
  PROVENANCE_DEFAULT_TRACKED_TYPES: ['Indicator', 'Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual', 'Malware', 'uses', 'IPv4-Addr'],
  PROVENANCE_RECOMMENDED_RELATIONSHIP_TYPES: ['uses', 'targets', 'attributed-to'],
}));

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/cache')>(),
  getEntitiesListFromCache: vi.fn(),
}));

const context = { source: 'provenance-tracking-test' } as AuthContext;
const setting = (targetType: string, provenanceTracking?: boolean) => ({ target_type: targetType, provenance_tracking: provenanceTracking }) as BasicStoreEntityEntitySetting;
const relationshipSetting = (types: Record<string, boolean>, provenanceTracking?: boolean) => ({
  ...setting('stix-core-relationship', provenanceTracking),
  provenance_relationship_types: JSON.stringify(types),
}) as BasicStoreEntityEntitySetting;
const keys = (layout: Array<{ key: string }> | undefined) => (layout ?? []).map(({ key }) => key);

describe('Provenance tracking per entity type', () => {
  beforeEach(() => {
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([]);
  });

  it('should follow the entity setting, otherwise the default tracked types', () => {
    expect(isProvenanceTrackingEnabled(setting('Intrusion-Set'))).toEqual(true);
    expect(isProvenanceTrackingEnabled(setting('Attack-Pattern'))).toEqual(false);
    expect(isProvenanceTrackingEnabled(setting('Attack-Pattern', true))).toEqual(true);
    expect(isProvenanceTrackingEnabled(setting('Malware', false))).toEqual(false);
    // The relationships setting is tracked while one relationship type is
    expect(isProvenanceTrackingEnabled(setting('stix-core-relationship'))).toEqual(true);
    expect(isProvenanceTrackingEnabled(setting('stix-core-relationship', false))).toEqual(false);
    expect(isProvenanceTrackingEnabled(relationshipSetting({ targets: true }, false))).toEqual(true);
  });

  it('should follow the switch of each relationship type before the value of the relationships setting', async () => {
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([relationshipSetting({ uses: false, targets: true })]);
    expect(await isProvenanceTrackedForType(context, 'uses')).toEqual(false);
    expect(await isProvenanceTrackedForType(context, 'targets')).toEqual(true);
    // Absent from the map: the platform default of the type
    expect(await isProvenanceTrackedForType(context, 'indicates')).toEqual(false);
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([relationshipSetting({ uses: false }, true)]);
    expect(await isProvenanceTrackedForType(context, 'uses')).toEqual(false);
    expect(await isProvenanceTrackedForType(context, 'indicates')).toEqual(true);
    const untracked = await listProvenanceUntrackedTypesOfSetting(context, relationshipSetting({ uses: false }, true));
    expect(untracked).toEqual(['uses']);
  });

  it('should list the tracking of every relationship type with the recommended ones', () => {
    const tracking = listProvenanceRelationshipTracking(relationshipSetting({ indicates: true, uses: false }));
    const byType = new Map(tracking.map((entry) => [entry.relationship_type, entry]));
    expect(byType.get('uses')).toEqual({ relationship_type: 'uses', tracked: false, recommended: true });
    expect(byType.get('indicates')).toEqual({ relationship_type: 'indicates', tracked: true, recommended: false });
    expect(byType.get('targets')).toEqual({ relationship_type: 'targets', tracked: false, recommended: true });
    expect(tracking.filter((entry) => entry.recommended).map((entry) => entry.relationship_type).sort()).toEqual(['attributed-to', 'targets', 'uses']);
    expect(listProvenanceRelationshipTracking(setting('Malware'))).toEqual([]);
  });

  it('should ignore the values of the map that are not relationship type switches', () => {
    expect(parseProvenanceRelationshipTypes('{"uses":true,"Malware":true,"targets":"yes"}')).toEqual({ uses: true });
    expect(parseProvenanceRelationshipTypes('not json')).toEqual({});
    expect(parseProvenanceRelationshipTypes(null)).toEqual({});
    expect(() => parseProvenanceRelationshipTypesStrict('[]')).toThrow();
    expect(JSON.parse(PROVENANCE_RECOMMENDED_RELATIONSHIP_TYPES_SETTING)).toEqual({ uses: true, targets: true, 'attributed-to': true });
  });

  it('should never track the types on which provenance is not available', () => {
    expect(isProvenanceTrackingEnabled(setting('External-Reference', true))).toEqual(false);
  });

  it('should inherit the setting of the abstract type for relationships', async () => {
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([setting('stix-core-relationship', true), setting('Malware', false)]);
    expect(await isProvenanceTrackedForType(context, 'uses')).toEqual(true);
    expect(await isProvenanceTrackedForType(context, 'Malware')).toEqual(false);
    expect(await isProvenanceTrackedForType(context, 'Intrusion-Set')).toEqual(true);
    const tracked = await listProvenanceTrackedTypes(context);
    expect(tracked).toEqual(expect.arrayContaining(['uses', 'indicates', 'Intrusion-Set', 'Indicator']));
    expect(tracked).not.toContain('Malware');
    expect(tracked).not.toContain('Attack-Pattern');
    expect(tracked).not.toContain('stix-sighting-relationship');
  });

  it('should evaluate an unset inherited setting against the concrete type, and keep an explicit inherited value', async () => {
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([setting('stix-core-relationship'), setting('Stix-Cyber-Observable')]);
    expect(await isProvenanceTrackedForType(context, 'uses')).toEqual(true);
    expect(await isProvenanceTrackedForType(context, 'targets')).toEqual(false);
    expect(await isProvenanceTrackedForType(context, 'IPv4-Addr')).toEqual(true);
    expect(await isProvenanceTrackedForType(context, 'Domain-Name')).toEqual(false);
    const untrackedRelationships = await listProvenanceUntrackedTypesOfSetting(context, setting('stix-core-relationship'));
    expect(untrackedRelationships).toContain('targets');
    expect(untrackedRelationships).not.toContain('uses');
    const untrackedObservables = await listProvenanceUntrackedTypesOfSetting(context, setting('Stix-Cyber-Observable'));
    expect(untrackedObservables).toContain('Domain-Name');
    expect(untrackedObservables).not.toContain('IPv4-Addr');
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([setting('stix-core-relationship', false)]);
    expect(await isProvenanceTrackedForType(context, 'uses')).toEqual(false);
    expect(await listProvenanceUntrackedTypesOfSetting(context, setting('stix-core-relationship', false))).toContain('uses');
    expect(await listProvenanceUntrackedTypesOfSetting(context, setting('Intrusion-Set'))).toEqual([]);
    expect(await listProvenanceUntrackedTypesOfSetting(context, setting('Attack-Pattern'))).toEqual(['Attack-Pattern']);
  });

  it('should restrict the provenance statistics to the tracked types', async () => {
    const tracked = await listProvenanceTrackedTypes(context);
    const everything = resolveStatisticsTypes(null, tracked);
    expect(everything).toEqual(expect.arrayContaining(['Malware', 'Intrusion-Set', 'uses', 'IPv4-Addr']));
    expect(everything).not.toContain('Report');
    expect(everything).not.toContain('targets');
    expect(everything).not.toContain('stix-sighting-relationship');
    const domainObjects = resolveStatisticsTypes(['Stix-Domain-Object'], tracked);
    expect(domainObjects).toContain('Malware');
    expect(domainObjects).not.toContain('IPv4-Addr');
    expect(resolveStatisticsTypes(['Report', 'targets'], tracked)).toEqual([]);
  });
});

describe('Procedures preservation, a setting of relationships', () => {
  it('should follow the relationship entity setting for uses relationships to attack patterns', async () => {
    const input = { description: 'Spearphishing with macros', to: { entity_type: 'Attack-Pattern' } };
    const preservationDisabled = { ...setting('stix-core-relationship', true), procedures_preservation: false } as BasicStoreEntityEntitySetting;
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([preservationDisabled]);
    expect(await creationProceduresBuilder(context, 'uses', input)).toBeUndefined();
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([setting('stix-core-relationship', true)]);
    expect(await creationProceduresBuilder(context, 'uses', input)).toBeTypeOf('function');
  });
});

describe('Overview layout with the Sources widget', () => {
  it('should insert the half-width Sources widget right after the basic information of a tracked type only', () => {
    const layout = getOverviewLayoutCustomization(setting('Intrusion-Set'));
    expect(keys(layout)).toEqual([
      'details', 'basicInformation', 'sources', 'latestCreatedRelationships', 'latestContainers', 'externalReferences', 'mostRecentHistory', 'notes',
    ]);
    expect(layout?.find((widget) => widget.key === 'sources')?.width).toEqual(6);
    expect(keys(getOverviewLayoutCustomization(setting('Attack-Pattern')))).not.toContain('sources');
    // provenance:enabled=false switches the whole module off, the Sources widget included
    expect(keys(getOverviewLayoutCustomization(setting('Intrusion-Set'), false))).not.toContain('sources');
  });

  it('should pair the Sources widget with the timeline that follows the basic information', () => {
    const withTimeline = [
      { key: 'details', width: 6, label: 'Entity details' },
      { key: 'basicInformation', width: 6, label: 'Basic information' },
      { key: 'timeline', width: 6, label: 'Timeline' },
      { key: 'notes', width: 12, label: 'Notes about this entity' },
    ];
    expect(keys(insertSourcesWidget(withTimeline))).toEqual(['details', 'basicInformation', 'timeline', 'sources', 'notes']);
    const timelineElsewhere = [withTimeline[2], withTimeline[0], withTimeline[1], withTimeline[3]];
    expect(keys(insertSourcesWidget(timelineElsewhere))).toEqual(['timeline', 'details', 'basicInformation', 'sources', 'notes']);
    expect(keys(insertSourcesWidget([withTimeline[0], withTimeline[3]]))).toEqual(['details', 'notes', 'sources']);
  });

  it('should complete a customized layout with the widgets registered since, and drop Sources when not tracked', () => {
    const stored = [
      { key: 'notes', width: 12, label: 'Notes about this entity' },
      { key: 'details', width: 6, label: 'Entity details' },
      { key: 'basicInformation', width: 6, label: 'Basic information' },
      { key: 'latestCreatedRelationships', width: 6, label: 'Latest created relationships' },
      { key: 'latestContainers', width: 6, label: 'Latest containers' },
      { key: 'externalReferences', width: 6, label: 'External references' },
      { key: 'mostRecentHistory', width: 6, label: 'Most recent history' },
    ];
    const tracked = { ...setting('Malware'), overview_layout_customization: stored };
    const completed = getOverviewLayoutCustomization(tracked);
    expect(keys(completed)).toEqual([
      'notes', 'details', 'basicInformation', 'sources', 'latestCreatedRelationships', 'latestContainers', 'externalReferences', 'mostRecentHistory',
    ]);
    expect(completed?.find((widget) => widget.key === 'sources')?.width).toEqual(6);
    const customizedSources = [...stored, { key: 'sources', width: 12, label: 'Sources' }];
    expect(getOverviewLayoutCustomization({ ...tracked, overview_layout_customization: customizedSources })).toEqual(customizedSources);
    const untracked = { ...setting('Malware', false), overview_layout_customization: [...stored, { key: 'sources', width: 12, label: 'Sources' }] };
    expect(keys(getOverviewLayoutCustomization(untracked))).not.toContain('sources');
  });

  it('should append the widgets that have no registered successor in the customized layout', () => {
    const merged = mergeMissingWidgets([{ key: 'b', width: 6, label: 'B' }], [
      { key: 'a', width: 6, label: 'A' }, { key: 'b', width: 6, label: 'B' }, { key: 'c', width: 12, label: 'C' },
    ]);
    expect(keys(merged)).toEqual(['a', 'b', 'c']);
  });
});
