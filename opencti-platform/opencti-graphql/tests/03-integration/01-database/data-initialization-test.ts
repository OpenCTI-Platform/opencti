import { describe, expect, it } from 'vitest';
import { fullEntitiesList } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE, ENTITY_TYPE_SETTINGS } from '../../../src/schema/internalObject';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import type { BasicStoreEntity } from '../../../src/types/store';
import { loadEntity } from '../../../src/database/middleware';
import { setPlatformId } from '../../../src/database/data-initialization';
import { entitiesCounter } from '../../utils/entityCountHelper';

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

  it('should create all initial Groups', async () => {
    const allGroups = await fullEntitiesList<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_GROUP]);
    const allGroupsNames = allGroups.map((group) => group.name).sort();
    const allExpectedGroups = ['Administrators', 'Connectors', 'Default'];
    for (let i = 0; i < allExpectedGroups.length; i += 1) {
      expect(allGroupsNames, `${allExpectedGroups[i]} Group is missing from initialization`).toContain(allExpectedGroups[i]);
    }
  });
});
