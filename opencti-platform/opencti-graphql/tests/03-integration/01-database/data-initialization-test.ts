import { describe, expect, it } from 'vitest';
import { fullEntitiesList, fullEntitiesThroughRelationsToList, storeLoadById } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE, ENTITY_TYPE_SETTINGS, ENTITY_TYPE_STATUS, ENTITY_TYPE_STATUS_TEMPLATE } from '../../../src/schema/internalObject';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import type { BasicStoreEntity } from '../../../src/types/store';
import { loadEntity } from '../../../src/database/middleware';
import { setPlatformId } from '../../../src/database/data-initialization';
import { entitiesCounter } from '../../02-dataInjection/01-dataCount/entityCountHelper';
import { RELATION_HAS_CAPABILITY } from '../../../src/schema/internalRelationship';
import { listRules } from '../../../src/modules/retentionRules/retentionRules-domain';
import type { BasicStoreEntityRetentionRule } from '../../../src/modules/retentionRules/retentionRules-types';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../src/schema/stixMetaObject';
import { MARKING_TLP_AMBER, MARKING_TLP_AMBER_STRICT, MARKING_TLP_CLEAR, MARKING_TLP_GREEN, MARKING_TLP_RED } from '../../../src/schema/identifier';
import { ENTITY_TYPE_VOCABULARY } from '../../../src/modules/vocabulary/vocabulary-types';
import { openVocabularies } from '../../../src/modules/vocabulary/vocabulary-utils';
import { VocabularyCategory } from '../../../src/generated/graphql';
import { findByType as findEntitySettingsByType } from '../../../src/modules/entitySetting/entitySetting-domain';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../../src/modules/case/case-rfi/case-rfi-types';
import type { BasicWorkflowStatus } from '../../../src/types/store';

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

  it('should create all TLP marking definitions', async () => {
    const tlpMarkingIds = [MARKING_TLP_CLEAR, MARKING_TLP_GREEN, MARKING_TLP_AMBER, MARKING_TLP_AMBER_STRICT, MARKING_TLP_RED];
    const expectedDefinitions = ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED'];

    for (let i = 0; i < tlpMarkingIds.length; i += 1) {
      const marking = await storeLoadById(testContext, ADMIN_USER, tlpMarkingIds[i], ENTITY_TYPE_MARKING_DEFINITION);
      expect(marking, `TLP marking "${expectedDefinitions[i]}" is missing from initialization`).toBeDefined();
      expect(marking.definition_type).toBe('TLP');
      expect(marking.definition).toBe(expectedDefinitions[i]);
    }
  });

  it('should create all PAP marking definitions', async () => {
    const allMarkings = await fullEntitiesList<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_MARKING_DEFINITION]);
    const papMarkings = allMarkings.filter((m) => m.definition_type === 'PAP');

    const expectedPapDefinitions = ['PAP:CLEAR', 'PAP:GREEN', 'PAP:AMBER', 'PAP:RED'];
    expect(papMarkings.length, 'Expected 4 PAP marking definitions to be created').toBe(4);

    const papDefinitionNames = papMarkings.map((m) => m.definition).sort();
    expect(papDefinitionNames).toEqual([...expectedPapDefinitions].sort());
  });

  it('should create vocabularies for all categories', async () => {
    const allVocabularies = await fullEntitiesList<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_VOCABULARY]);
    expect(allVocabularies.length, 'Expected vocabularies to be initialized').toBeGreaterThan(0);

    // Verify at least one representative category has its entries
    const categories = Object.values(VocabularyCategory);
    for (const category of categories) {
      const expectedVocabs = openVocabularies[category] ?? [];
      if (expectedVocabs.length > 0) {
        const createdForCategory = allVocabularies.filter((v) => v.category === category);
        expect(
          createdForCategory.length,
          `Expected ${expectedVocabs.length} vocabularies for category "${category}", got ${createdForCategory.length}`,
        ).toBe(expectedVocabs.length);
      }
    }
  });

  it('should create all default status templates', async () => {
    const allTemplates = await fullEntitiesList<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_STATUS_TEMPLATE]);
    const templateNames = allTemplates.map((t) => t.name);

    const expectedTemplates = ['NEW', 'IN_PROGRESS', 'PENDING', 'TO_BE_QUALIFIED', 'ANALYZED', 'CLOSED'];
    for (const name of expectedTemplates) {
      expect(templateNames, `Status template "${name}" is missing from initialization`).toContain(name);
    }
  });

  it('should create default statuses for Report entity type', async () => {
    const allStatuses = await fullEntitiesList<BasicWorkflowStatus>(testContext, ADMIN_USER, [ENTITY_TYPE_STATUS]);
    const reportStatuses = allStatuses.filter((s) => s.type === 'Report');

    expect(reportStatuses.length, 'Expected 4 default statuses to be created for Report').toBe(4);
    const statusOrders = reportStatuses.map((s) => s.order).sort((a, b) => a - b);
    expect(statusOrders).toEqual([1, 2, 3, 4]);
  });

  it('should configure the initial request access workflow for CaseRFI', async () => {
    const rfiEntitySettings = await findEntitySettingsByType(testContext, ADMIN_USER, ENTITY_TYPE_CONTAINER_CASE_RFI);
    expect(rfiEntitySettings, 'CaseRFI entity settings should be defined after initialization').toBeDefined();
    expect(
      rfiEntitySettings!.request_access_workflow,
      'CaseRFI entity settings should have a request_access_workflow configured',
    ).toBeDefined();

    const workflow = rfiEntitySettings!.request_access_workflow as { approved_workflow_id: string; declined_workflow_id: string };
    expect(workflow.approved_workflow_id, 'request_access_workflow should have an approved_workflow_id').toBeDefined();
    expect(workflow.declined_workflow_id, 'request_access_workflow should have a declined_workflow_id').toBeDefined();
  });

  it('should initialize default platform settings', async () => {
    const platformSettings = await loadEntity(testContext, ADMIN_USER, [ENTITY_TYPE_SETTINGS]);
    expect(platformSettings, 'Platform settings should exist after initialization').toBeDefined();
    expect(platformSettings.platform_title).toBe('OpenCTI - Cyber Threat Intelligence Platform');
    expect(platformSettings.platform_email).toBe('admin@opencti.io');
    expect(platformSettings.platform_language).toBe('auto');
  });
});
