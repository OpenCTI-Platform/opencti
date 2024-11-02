import { describe, expect, it } from 'vitest';
import { listAllEntities } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE } from '../../../src/schema/internalObject';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import type { BasicStoreEntity } from '../../../src/types/store';

describe('Data initialization test', () => {
  it('should create all capabilities', async () => {
    const capabilities = await listAllEntities<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_CAPABILITY]);
    expect(capabilities.length).toEqual(39);
    const capabilitiesNames = capabilities.map((capa) => capa.name).sort();
    const allExpectedNames = [
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
      'KNOWLEDGE_KNUPDATE_KNORGARESTRICT',
      'KNOWLEDGE_KNUPLOAD',
      'MODULES',
      'MODULES_MODMANAGE',
      'SETTINGS',
      'SETTINGS_FILEINDEXING',
      'SETTINGS_SECURITYACTIVITY',
      'SETTINGS_SETACCESSES',
      'SETTINGS_SETCUSTOMIZATION',
      'SETTINGS_SETLABELS',
      'SETTINGS_SETMARKINGS',
      'SETTINGS_SETPARAMETERS',
      'SETTINGS_SUPPORT',
      'TAXIIAPI',
      'TAXIIAPI_SETCOLLECTIONS',
    ];
    expect(capabilitiesNames).toEqual(allExpectedNames);
  });

  it('should create all initial roles', async () => {
    const allRoles = await listAllEntities<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_ROLE]);
    const allRolesNames = allRoles.map((role) => role.name).sort();
    const allExpectedRoles = ['Administrator', 'Connector', 'Default'];
    for (let i = 0; i < allExpectedRoles.length; i += 1) {
      expect(allRolesNames, `${allExpectedRoles[i]} Role is missing from initialization`).toContain(allExpectedRoles[i]);
    }
  });

  it('should create all initial Groups', async () => {
    const allGroups = await listAllEntities<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_GROUP]);
    const allGroupsNames = allGroups.map((group) => group.name).sort();
    const allExpectedGroups = ['Administrators', 'Connectors', 'Default'];
    for (let i = 0; i < allExpectedGroups.length; i += 1) {
      expect(allGroupsNames, `${allExpectedGroups[i]} Group is missing from initialization`).toContain(allExpectedGroups[i]);
    }
  });
});
