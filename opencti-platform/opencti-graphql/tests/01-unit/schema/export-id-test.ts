import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import { buildEntityData } from '../../../src/database/data-builder';
import { EXPORT_ID_ON_CREATION_TYPES, exportIdOnCreationQuery, isExportIdOnCreation } from '../../../src/schema/export-id';
import { SYSTEM_USER } from '../../../src/utils/access';

const context = { source: 'testing' } as any;

describe('Configuration entities export_id', () => {
  it('should give an export_id to every element of a configuration type', () => {
    EXPORT_ID_ON_CREATION_TYPES.forEach((type) => {
      expect(isExportIdOnCreation(type, {})).toBe(true);
    });
  });

  it('should give an export_id to dashboards only, not to investigations', () => {
    expect(isExportIdOnCreation('Workspace', { type: 'dashboard' })).toBe(true);
    expect(isExportIdOnCreation('Workspace', { type: 'investigation' })).toBe(false);
  });

  it('should give an export_id to managed connectors only', () => {
    expect(isExportIdOnCreation('Connector', { catalog_id: 'catalog-id' })).toBe(true);
    expect(isExportIdOnCreation('Connector', {})).toBe(false);
  });

  it('should give an export_id to custom decay rules only', () => {
    expect(isExportIdOnCreation('DecayRule', { built_in: false })).toBe(true);
    expect(isExportIdOnCreation('DecayRule', { built_in: true })).toBe(false);
  });

  it('should not give an export_id to knowledge or other internal objects', () => {
    expect(isExportIdOnCreation('Malware', {})).toBe(false);
    expect(isExportIdOnCreation('User', {})).toBe(false);
  });

  it('should query the same elements in the migration', () => {
    const query = exportIdOnCreationQuery();
    expect(query.bool.minimum_should_match).toBe(1);
    expect(query.bool.should).toEqual([
      { terms: { 'entity_type.keyword': EXPORT_ID_ON_CREATION_TYPES } },
      { bool: { must: [{ term: { 'entity_type.keyword': { value: 'Workspace' } } }, { term: { 'type.keyword': { value: 'dashboard' } } }] } },
      { bool: { must: [{ term: { 'entity_type.keyword': { value: 'Connector' } } }, { exists: { field: 'catalog_id' } }] } },
      { bool: { must: [{ term: { 'entity_type.keyword': { value: 'DecayRule' } } }], must_not: [{ term: { built_in: true } }] } },
    ]);
  });
});

const buildElement = async (input: Record<string, any>) => {
  const { element } = await buildEntityData(context, SYSTEM_USER, input, input.entity_type);
  return element as Record<string, any>;
};

describe('Configuration entities creation export_id', () => {
  it('should use the internal_id as export_id', async () => {
    const element = await buildElement({ entity_type: 'Playbook', name: 'My playbook' });
    expect(element.export_id).toBeDefined();
    expect(element.export_id).toBe(element.internal_id);
  });

  it('should keep the export_id given at creation', async () => {
    const element = await buildElement({ entity_type: 'StatusTemplate', name: 'NEW', export_id: 'built-in-export-id' });
    expect(element.export_id).toBe('built-in-export-id');
  });

  it('should not give an export_id to an investigation', async () => {
    const element = await buildElement({ entity_type: 'Workspace', name: 'My investigation', type: 'investigation' });
    expect(element.export_id).toBeUndefined();
  });
});
