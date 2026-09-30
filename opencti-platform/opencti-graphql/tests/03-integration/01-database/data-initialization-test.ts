import { describe, expect, it, vi } from 'vitest';
import { fullEntitiesList, fullEntitiesThroughRelationsToList } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE, ENTITY_TYPE_SETTINGS } from '../../../src/schema/internalObject';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import type { BasicStoreEntity } from '../../../src/types/store';
import { loadEntity } from '../../../src/database/middleware';
import { createDefaultRetentionRules, setPlatformId } from '../../../src/database/data-initialization';
import { entitiesCounter } from '../../02-dataInjection/01-dataCount/entityCountHelper';
import { RELATION_HAS_CAPABILITY } from '../../../src/schema/internalRelationship';
import { listRules, deleteRetentionRule } from '../../../src/modules/retentionRules/retentionRules-domain';
import type { BasicStoreEntityRetentionRule } from '../../../src/modules/retentionRules/retentionRules-types';
import { elList, elUpdate } from '../../../src/database/engine';
import { READ_INDEX_INTERNAL_OBJECTS, READ_INDEX_STIX_META_OBJECTS } from '../../../src/database/utils';
import { generateBuiltInExportId } from '../../../src/schema/identifier';
import { logApp } from '../../../src/config/conf';
import {
  BUILT_IN_EXPORT_ID_TYPES,
  computeMissingBuiltInExportIds,
  findMissingBuiltInElements,
  up as addExportIdMigration,
} from '../../../src/migrations/1790755214072-add-export-id-to-built-in-entities';

describe('Data initialization test', () => {
  it('should have a specific platform_id from config file', async () => {
    const platformSettings = await loadEntity(testContext, ADMIN_USER, [ENTITY_TYPE_SETTINGS]);
    // as configured in test.json
    expect(platformSettings?.id).toEqual('7992a4b1-128c-4656-bf97-2018b6f1f395');
  });

  it('should be able to set another platform_id', async () => {
    await setPlatformId(testContext, '74cc0eba-b0c6-4822-8db6-6ddbdf49498f');
    const platformSettings = await loadEntity(testContext, ADMIN_USER, [ENTITY_TYPE_SETTINGS]);
    expect(platformSettings?.id).toEqual('74cc0eba-b0c6-4822-8db6-6ddbdf49498f');
    // restore initial id
    await setPlatformId(testContext, '7992a4b1-128c-4656-bf97-2018b6f1f395');
  });

  it('should not be able to set a platform_id that is not a valid uuid', async () => {
    await expect(async () => {
      await setPlatformId(testContext, 'wrong-id');
    }).rejects.toThrowError('Cannot switch platform identifier: platform_id is not a valid UUID');
  });

  it('should create all capabilities', async () => {
    const capabilities = await fullEntitiesList<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_CAPABILITY]);
    expect(capabilities.length).toEqual(entitiesCounter.Capability);
    const capabilitiesNames = capabilities.map((capa) => capa.name).sort();
    const allExpectedNames = [
      'APIACCESS',
      'APIACCESS_USEBASICAUTH',
      'APIACCESS_USETOKEN',
      'AUTOMATION',
      'AUTOMATION_AUTMANAGE',
      'BYPASS',
      'CONNECTORAPI',
      'CSVMAPPERS',
      'EXPLORE',
      'EXPLORE_EXUPDATE',
      'EXPLORE_EXUPDATE_EXDELETE',
      'EXPLORE_EXUPDATE_PUBLISH',
      'INGESTION',
      'INGESTION_SETINGESTIONS',
      'INVESTIGATION',
      'INVESTIGATION_INUPDATE',
      'INVESTIGATION_INUPDATE_INDELETE',
      'KNOWLEDGE',
      'KNOWLEDGE_KNASKIMPORT',
      'KNOWLEDGE_KNDISSEMINATION',
      'KNOWLEDGE_KNENRICHMENT',
      'KNOWLEDGE_KNFRONTENDEXPORT',
      'KNOWLEDGE_KNGETEXPORT',
      'KNOWLEDGE_KNGETEXPORT_KNASKEXPORT',
      'KNOWLEDGE_KNPARTICIPATE',
      'KNOWLEDGE_KNSHAREFILTERS',
      'KNOWLEDGE_KNUPDATE',
      'KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS',
      'KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE',
      'KNOWLEDGE_KNUPDATE_KNDELETE',
      'KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS',
      'KNOWLEDGE_KNUPDATE_KNMERGE',
      'KNOWLEDGE_KNUPDATE_KNORGARESTRICT',
      'KNOWLEDGE_KNUPLOAD',
      'MODULES',
      'MODULES_MODMANAGE',
      'PIRAPI',
      'PIRAPI_PIRUPDATE',
      'SETTINGS',
      'SETTINGS_FILEINDEXING',
      'SETTINGS_SECURITYACTIVITY',
      'SETTINGS_SETACCESSES',
      'SETTINGS_SETAUTH',
      'SETTINGS_SETCASETEMPLATES',
      'SETTINGS_SETCUSTOMIZATION',
      'SETTINGS_SETDISSEMINATION',
      'SETTINGS_SETKILLCHAINPHASES',
      'SETTINGS_SETLABELS',
      'SETTINGS_SETMANAGEXTMHUB',
      'SETTINGS_SETMARKINGS',
      'SETTINGS_SETPARAMETERS',
      'SETTINGS_SETSTATUSTEMPLATES',
      'SETTINGS_SETVOCABULARIES',
      'SETTINGS_SUPPORT',
      'TAXIIAPI',
      'TAXIIAPI_SETCOLLECTIONS',
    ];
    expect(capabilitiesNames).toEqual(allExpectedNames);
  });

  it('should create all initial roles', async () => {
    const allRoles = await fullEntitiesList<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_ROLE]);
    const allRolesNames = allRoles.map((role) => role.name).sort();
    const allExpectedRoles = ['Administrator', 'Connector', 'Default'];
    for (let i = 0; i < allExpectedRoles.length; i += 1) {
      expect(allRolesNames, `${allExpectedRoles[i]} Role is missing from initialization`).toContain(allExpectedRoles[i]);
    }
  });

  it('should not grant ingestion management to Connector role on initialization', async () => {
    const roles = await fullEntitiesList<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_ROLE]);
    const connectorRole = roles.find((role) => role.name === 'Connector');
    expect(connectorRole).toBeDefined();

    const connectorCapabilities = await fullEntitiesThroughRelationsToList<BasicStoreEntity>(
      testContext,
      ADMIN_USER,
      connectorRole!.id,
      RELATION_HAS_CAPABILITY,
      ENTITY_TYPE_CAPABILITY,
    );
    const connectorCapabilityNames = connectorCapabilities.map((capability) => capability.name);

    expect(connectorCapabilityNames).toContain('CONNECTORAPI');
    expect(connectorCapabilityNames).not.toContain('INGESTION');
    expect(connectorCapabilityNames).not.toContain('INGESTION_SETINGESTIONS');
  });

  it('should create all initial Groups', async () => {
    const allGroups = await fullEntitiesList<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_GROUP]);
    const allGroupsNames = allGroups.map((group) => group.name).sort();
    const allExpectedGroups = ['Administrators', 'Connectors', 'Default'];
    for (let i = 0; i < allExpectedGroups.length; i += 1) {
      expect(allGroupsNames, `${allExpectedGroups[i]} Group is missing from initialization`).toContain(allExpectedGroups[i]);
    }
  });

  it('should create all default disabled retention rules', async () => {
    const allRules = await listRules(testContext, ADMIN_USER, {}) as BasicStoreEntityRetentionRule[];
    const expectedScopes = ['file', 'workbench', 'history', 'activity'];

    for (const scope of expectedScopes) {
      const rule = allRules.find((r) => r.scope === scope);
      expect(rule, `Default retention rule for scope "${scope}" is missing from initialization`).toBeDefined();
      expect(rule!.active, `Default retention rule for scope "${scope}" should be inactive`).toBe(false);
      expect(rule!.max_retention, `Default retention rule for scope "${scope}" should have 30 days max_retention`).toBe(30);
      expect(rule!.retention_unit, `Default retention rule for scope "${scope}" should use "days" unit`).toBe('days');
    }
  });

  it('should create default retention rules when createDefaultRetentionRules is called directly', async () => {
    // Collect IDs of existing rules before calling the function, so we can clean up duplicates
    const rulesBefore = await listRules(testContext, ADMIN_USER, {}) as BasicStoreEntityRetentionRule[];
    const idsBefore = new Set(rulesBefore.map((r) => r.id));

    // Call the function directly – this is what data-initialization calls during platform boot
    await createDefaultRetentionRules(testContext);

    // Verify new rules were created for all expected scopes
    const rulesAfter = await listRules(testContext, ADMIN_USER, {}) as BasicStoreEntityRetentionRule[];
    const newRules = rulesAfter.filter((r) => !idsBefore.has(r.id));
    const expectedScopes = ['file', 'workbench', 'history', 'activity'];
    for (const scope of expectedScopes) {
      const newRule = newRules.find((r) => r.scope === scope);
      expect(newRule, `createDefaultRetentionRules should create a "${scope}" rule`).toBeDefined();
      expect(newRule!.active).toBe(false);
      expect(newRule!.max_retention).toBe(30);
      expect(newRule!.retention_unit).toBe('days');
    }

    // Cleanup: delete the newly created duplicate rules
    await Promise.all(newRules.map((r) => deleteRetentionRule(testContext, ADMIN_USER, r.id)));
  });
});

describe('Built-in entities export_id', () => {
  const listBuiltInCandidates = () => {
    return elList<any>(testContext, ADMIN_USER, [READ_INDEX_INTERNAL_OBJECTS, READ_INDEX_STIX_META_OBJECTS], { types: BUILT_IN_EXPORT_ID_TYPES });
  };
  const findElement = (elements: any[], entityType: string, predicate: (element: any) => boolean = () => true) => {
    return elements.find((element) => element.entity_type === entityType && predicate(element));
  };

  it('should give a stable export_id to built-in entities at initialization', async () => {
    const elements = await listBuiltInCandidates();
    const expectations: [string, (element: any) => boolean, Record<string, string>][] = [
      ['Settings', () => true, {}],
      ['EntitySetting', (e) => e.target_type === 'Report', { target_type: 'Report' }],
      ['ManagerConfiguration', (e) => e.manager_id === 'FILE_INDEX_MANAGER', { manager_id: 'FILE_INDEX_MANAGER' }],
      ['Capability', (e) => e.name === 'BYPASS', { name: 'BYPASS' }],
      ['Role', (e) => e.name === 'Administrator', { name: 'Administrator' }],
      ['Group', (e) => e.name === 'Administrators', { name: 'Administrators' }],
      ['StatusTemplate', (e) => e.name === 'IN_PROGRESS', { name: 'IN_PROGRESS' }],
      ['Vocabulary', (e) => e.category === 'report_types_ov' && e.name === 'threat-report', { category: 'report_types_ov', name: 'threat-report' }],
      ['Marking-Definition', (e) => e.definition === 'TLP:AMBER+STRICT', { definition_type: 'TLP', definition: 'TLP:AMBER+STRICT' }],
      ['Theme', (e) => e.name === 'Filigran Light', { name: 'Filigran Light' }],
      ['DecayRule', (e) => e.name === 'Built-in default', { name: 'Built-in default' }],
      ['EmailTemplate', (e) => e.name === 'Built-In Template For Onboarding', { name: 'Built-In Template For Onboarding' }],
      ['RetentionRule', (e) => e.scope === 'activity', { scope: 'activity' }],
      ['Notifier', (e) => e.name === 'Sample of Microsoft Teams message for digest trigger', { name: 'Sample of Microsoft Teams message for digest trigger' }],
    ];
    expectations.forEach(([entityType, predicate, naturalKey]) => {
      const builtIn = findElement(elements, entityType, predicate);
      expect(builtIn, `Built-in ${entityType} is missing`).toBeDefined();
      expect(builtIn.export_id, `Built-in ${entityType} has a wrong export_id`).toEqual(generateBuiltInExportId(entityType, naturalKey));
    });
    // Statuses are identified by the name of their template
    const reportTemplate = findElement(elements, 'StatusTemplate', (e) => e.name === 'ANALYZED');
    const reportStatus = findElement(elements, 'Status', (e) => e.type === 'Report' && e.template_id === reportTemplate.internal_id);
    expect(reportStatus.export_id).toEqual(generateBuiltInExportId('Status', { type: 'Report', scope: 'GLOBAL', template: 'ANALYZED' }));
    // Every capability and entity setting is built-in
    const allBuiltIn = elements.filter((e) => ['Capability', 'EntitySetting'].includes(e.entity_type));
    expect(allBuiltIn.filter((e) => !e.export_id)).toEqual([]);
  });

  it('should compute in the migration the same export_id as the initialization', async () => {
    const elements = await listBuiltInCandidates();
    const initializationExportIds = new Map(elements.map((e) => [e.internal_id, e.export_id]));
    const elementsWithoutExportId = elements.map(({ export_id: _, ...element }) => element);
    const assignments = computeMissingBuiltInExportIds(elementsWithoutExportId);
    expect(assignments.length).toBeGreaterThan(500);
    // Every element the migration recognizes gets the value computed at creation
    assignments.forEach(({ element, export_id }) => {
      expect(export_id, `${element.entity_type} ${element.internal_id}`).toEqual(initializationExportIds.get(element.internal_id));
    });
    // The migration finds every built-in element it expects. A failure means a built-in element was renamed or removed:
    // its export_id must stay the one of platforms created before. Fintel templates are not created by the test platform setup.
    expect(findMissingBuiltInElements(elements).filter((missing) => missing.entity_type !== 'FintelTemplate')).toEqual([]);
  });

  it('should add the missing export_id to built-in entities with the migration', async () => {
    const elements = await listBuiltInCandidates();
    const targets = [
      findElement(elements, 'Group', (e) => e.name === 'Connectors'),
      findElement(elements, 'Theme', (e) => e.name === 'Filigran Dark'),
      findElement(elements, 'Vocabulary', (e) => e.category === 'report_types_ov' && e.name === 'threat-report'),
      findElement(elements, 'RetentionRule', (e) => e.scope === 'file'),
      findElement(elements, 'Status', (e) => e.type === 'Case-Rfi'),
    ];
    // Simulate built-in entities created before the export_id existed
    for (let index = 0; index < targets.length; index += 1) {
      const target = targets[index];
      expect(target.export_id).toBeDefined();
      await elUpdate(testContext, target._index, target.internal_id, { script: { source: 'ctx._source.remove(\'export_id\')' } });
    }
    const withoutExportId = await listBuiltInCandidates();
    expect(computeMissingBuiltInExportIds(withoutExportId)).toHaveLength(targets.length);
    const warnSpy = vi.spyOn(logApp, 'warn');
    await addExportIdMigration(() => {});
    // The test platform setup does not create the fintel templates: the migration reports them
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('6 built-in FintelTemplate not found'));
    warnSpy.mockRestore();
    const migrated = await listBuiltInCandidates();
    targets.forEach((target) => {
      expect(findElement(migrated, target.entity_type, (e) => e.internal_id === target.internal_id).export_id).toEqual(target.export_id);
    });
    // Running it again changes nothing
    expect(computeMissingBuiltInExportIds(migrated)).toEqual([]);
  });
});
