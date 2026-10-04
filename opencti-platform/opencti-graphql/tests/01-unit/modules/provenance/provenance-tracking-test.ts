import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { getEntitiesListFromCache } from '../../../../src/database/cache';
import { isProvenanceTrackedForType, isProvenanceTrackingEnabled, listProvenanceTrackedTypes } from '../../../../src/modules/provenance/provenance-tracking';
import { getOverviewLayoutCustomization, mergeMissingWidgets } from '../../../../src/modules/entitySetting/entitySetting-domain';
import { creationProceduresBuilder } from '../../../../src/modules/provenance/provenance-upsert';
import type { BasicStoreEntityEntitySetting } from '../../../../src/modules/entitySetting/entitySetting-types';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/modules/provenance/provenance-config', () => ({
  PROVENANCE_ENABLED: true,
  PROVENANCE_REASSERTION_WINDOW_MS: 24 * 60 * 60 * 1000,
  PROVENANCE_DEFAULT_TRACKED_TYPES: ['Indicator', 'Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual', 'Malware'],
}));

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/cache')>(),
  getEntitiesListFromCache: vi.fn(),
}));

const context = { source: 'provenance-tracking-test' } as AuthContext;
const setting = (targetType: string, provenanceTracking?: boolean) => ({ target_type: targetType, provenance_tracking: provenanceTracking }) as BasicStoreEntityEntitySetting;
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
    expect(isProvenanceTrackingEnabled(setting('stix-core-relationship'))).toEqual(false);
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
  it('should insert the Sources widget before the notes of a tracked type only', () => {
    expect(keys(getOverviewLayoutCustomization(setting('Intrusion-Set')))).toEqual([
      'details', 'basicInformation', 'latestCreatedRelationships', 'latestContainers', 'externalReferences', 'mostRecentHistory', 'sources', 'notes',
    ]);
    expect(keys(getOverviewLayoutCustomization(setting('Attack-Pattern')))).not.toContain('sources');
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
    expect(keys(getOverviewLayoutCustomization(tracked))).toEqual([
      'sources', 'notes', 'details', 'basicInformation', 'latestCreatedRelationships', 'latestContainers', 'externalReferences', 'mostRecentHistory',
    ]);
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
