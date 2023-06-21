import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin, testContext } from '../../utils/testQuery';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_MALWARE
} from '../../../src/schema/stixDomainObject';
import { STIX_EXT_OCTI } from '../../../src/types/stix-extensions';
import {
  filterUpdateInstanceIdsFromDataContext,
  generateNotificationMessageForInstance,
  generateNotificationMessageForInstanceWithRefs,
  isRelationFromOrToMatchFilters
} from '../../../src/manager/notificationManager';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../src/schema/stixSightingRelationship';
import {
  generateInternalId,
  generateStandardId,
  MARKING_TLP_GREEN,
  MARKING_TLP_RED
} from '../../../src/schema/identifier';
import { ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import { RELATION_DELIVERS } from '../../../src/schema/stixCoreRelationship';
import { STIX_TYPE_RELATION, STIX_TYPE_SIGHTING } from '../../../src/schema/general';

const READ_QUERY = gql`
  query markingDefinition($id: String!) {
    markingDefinition(id: $id) {
      id
      definition_type
      definition
    }
  }
`;

describe('Notification manager behaviors test', async () => {
  // -- PREPARE --
  // markings
  let queryResult = await queryAsAdmin({
    query: READ_QUERY,
    variables: { id: MARKING_TLP_GREEN }
  });
  expect(queryResult).not.toBeNull();
  const internalMarkingGreenId = queryResult?.data?.markingDefinition.id;
  queryResult = await queryAsAdmin({
    query: READ_QUERY,
    variables: { id: MARKING_TLP_RED }
  });
  expect(queryResult).not.toBeNull();
  const internalMarkingRedId = queryResult?.data?.markingDefinition.id;
  // users
  const loggingUserId = generateStandardId(ENTITY_TYPE_USER, { user_email: 'user@opencti.io' });
  const context = testContext;
  const adminUser = ADMIN_USER;
  const loggingUser = {
    id: loggingUserId,
    internal_id: loggingUserId,
    individual_id: undefined,
    name: 'username',
    user_email: 'user@opencti.io',
    inside_platform_organization: true,
    origin: { user_id: loggingUserId },
    roles: [],
    groups: [],
    capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }],
    organizations: [],
    allowed_organizations: [],
    allowed_marking: [{ internal_id: internalMarkingGreenId }],
    default_marking: [],
    all_marking: [],
    api_token: '',
  };
  // data
  const reportId = generateInternalId();
  const malwareId = generateInternalId();
  const attackPatternId = generateInternalId();
  const organization1Id = generateInternalId();
  const organization2Id = generateInternalId();
  const stixReport = {
    name: 'report_name',
    id: reportId,
    type: ENTITY_TYPE_CONTAINER_REPORT,
    extensions: {
      [STIX_EXT_OCTI]: {
        type: ENTITY_TYPE_CONTAINER_REPORT
      }
    }
  };
  const organization1 = {
    name: 'organization1',
    id: organization1Id,
    type: ENTITY_TYPE_IDENTITY_ORGANIZATION,
    extensions: {
      [STIX_EXT_OCTI]: {
        type: ENTITY_TYPE_IDENTITY_ORGANIZATION
      }
    }
  };
  const organization2 = {
    name: 'organization2',
    id: organization2Id,
    type: ENTITY_TYPE_IDENTITY_ORGANIZATION,
    extensions: {
      [STIX_EXT_OCTI]: {
        type: ENTITY_TYPE_IDENTITY_ORGANIZATION
      }
    }
  };
  const stixMalware = {
    name: 'malware_name',
    id: malwareId,
    type: ENTITY_TYPE_MALWARE,
    extensions: {
      [STIX_EXT_OCTI]: {
        type: ENTITY_TYPE_MALWARE
      }
    }
  };
  const stixSightingRelationship = {
    name: 'sighting_name',
    type: STIX_TYPE_SIGHTING,
    sighting_of_ref: malwareId,
    where_sighted_refs: [reportId],
    extensions: {
      [STIX_EXT_OCTI]: {
        type: STIX_SIGHTING_RELATIONSHIP,

        sighting_of_ref_object_marking_refs: [internalMarkingGreenId],
        sighting_of_ref_granted_refs: [],
        sighting_of_type: ENTITY_TYPE_MALWARE,
        sighting_of_value: 'malware_entity',

        where_sighted_refs_object_marking_refs: [internalMarkingRedId],
        where_sighted_refs_granted_refs: [],
        where_sighted_types: [ENTITY_TYPE_CONTAINER_REPORT],
        where_sighted_values: ['report_entity'],
      }
    }
  };
  const stixCoreRelationship = {
    name: 'delivers relationship',
    type: STIX_TYPE_RELATION,
    relationship_type: RELATION_DELIVERS,
    source_ref: attackPatternId,
    target_ref: malwareId,
    extensions: {
      [STIX_EXT_OCTI]: {
        type: RELATION_DELIVERS,

        source_ref_object_marking_refs: [internalMarkingRedId],
        source_ref_granted_refs: [],
        source_type: ENTITY_TYPE_ATTACK_PATTERN,
        source_value: 'attack-pattern_entity',

        target_ref_object_marking_refs: [internalMarkingGreenId],
        target_ref_granted_refs: [],
        target_type: ENTITY_TYPE_MALWARE,
        target_value: ['malware_entity'],
      }
    }
  };

  it('Should generate a notification message for an instance with refs', async () => {
    let result = generateNotificationMessageForInstanceWithRefs(stixReport, [organization1, organization2], true);
    expect(result).toEqual('[report] report_name because of [organization] organization1,[organization] organization2');
    result = generateNotificationMessageForInstanceWithRefs(stixReport, [organization1], true);
    expect(result).toEqual('[report] report_name because of [organization] organization1');
    result = generateNotificationMessageForInstanceWithRefs(stixReport, [organization1, stixMalware], true);
    expect(result).toEqual('[report] report_name because of [organization] organization1,[malware] malware_name');
    result = generateNotificationMessageForInstanceWithRefs(stixCoreRelationship, [organization1, stixMalware], true);
    expect(result).toEqual('[relationship] attack-pattern_entity delivers malware_entity because of [organization] organization1,[malware] malware_name');

    result = generateNotificationMessageForInstanceWithRefs(stixReport, [organization1, organization2], false);
    expect(result).toEqual('[organization] organization1,[organization] organization2 in [report] report_name');
    result = generateNotificationMessageForInstanceWithRefs(stixReport, [organization1], false);
    expect(result).toEqual('[organization] organization1 in [report] report_name');
    result = generateNotificationMessageForInstanceWithRefs(stixReport, [organization1, stixMalware], false);
    expect(result).toEqual('[organization] organization1,[malware] malware_name in [report] report_name');
    result = generateNotificationMessageForInstanceWithRefs(stixCoreRelationship, [organization1, stixMalware], false);
    expect(result).toEqual('[organization] organization1,[malware] malware_name in [relationship] attack-pattern_entity delivers malware_entity');
  });
  it('Should generate a notification message for an instance', async () => {
    const result = await generateNotificationMessageForInstance(context, adminUser, stixReport);
    expect(result).toEqual('[report] report_name');
  });
  it('Should generate a notification message for a relationship', async () => {
    let result = await generateNotificationMessageForInstance(context, adminUser, stixSightingRelationship);
    expect(result).toEqual('[sighting] malware_entity sighted in/at report_entity');
    result = await generateNotificationMessageForInstance(context, loggingUser, stixSightingRelationship);
    expect(result).toEqual('[sighting] malware_entity sighted in/at Restricted');

    result = await generateNotificationMessageForInstance(context, adminUser, stixCoreRelationship);
    expect(result).toEqual('[relationship] attack-pattern_entity delivers malware_entity');
    result = await generateNotificationMessageForInstance(context, loggingUser, stixCoreRelationship);
    expect(result).toEqual('[relationship] Restricted delivers malware_entity');
  });
  it('Should indicate if a relation from/to contains an instance that is in an instances map', async () => {
    const instancesMap = new Map();
    let result = isRelationFromOrToMatchFilters(instancesMap, stixCoreRelationship);
    expect(result).toEqual(false);
    result = isRelationFromOrToMatchFilters(instancesMap, stixSightingRelationship);
    expect(result).toEqual(false);

    instancesMap.set(organization1.id, organization1);
    result = isRelationFromOrToMatchFilters(instancesMap, stixCoreRelationship);
    expect(result).toEqual(false);
    result = isRelationFromOrToMatchFilters(instancesMap, stixSightingRelationship);
    expect(result).toEqual(false);

    instancesMap.set(stixMalware.id, stixMalware);
    result = isRelationFromOrToMatchFilters(instancesMap, stixCoreRelationship);
    expect(result).toEqual(true);
    result = isRelationFromOrToMatchFilters(instancesMap, stixSightingRelationship);
    expect(result).toEqual(true);
  });
  it('Should return the instances that are in the dataContext and in the instances map', async () => {
    // -- PREPARE --
    const instancesMap = new Map([[organization1.id, organization1], [stixReport.id, stixReport]]);
    const dataContextAdd1 = {
      patch: [
        {
          path: 'granted_by_ref/1',
          value: organization2Id,
        }
      ],
      reverse_patch: [],
    };
    const dataContextAdd2 = {
      patch: [{
        path: 'created_by_ref/1',
        value: organization1Id,
      },
      {
        path: 'granted_by_ref/1',
        value: organization2Id,
      }
      ],
      reverse_patch: [],
    };
    const dataContextRemove = {
      patch: [{
        path: 'created_by_ref/1',
      }],
      reverse_patch: [{
        path: 'created_by_ref/1',
        value: organization1Id,
      }],
    };
    const dataContextMultiple = {
      patch: [{
        path: 'created_by_ref/1',
        value: organization1Id,
      }],
      reverse_patch: [{
        path: 'granted_by_ref/1',
        value: organization2Id,
      },
      {
        path: 'granted_by_ref/1',
        value: reportId,
      },
      ],
    };

    // ASSERT RESULTS
    let result = filterUpdateInstanceIdsFromDataContext(instancesMap, dataContextAdd1);
    expect(result.length).toEqual(0);
    expect(result).toEqual([]);

    result = filterUpdateInstanceIdsFromDataContext(instancesMap, dataContextAdd2);
    expect(result.length).toEqual(1);
    expect(result[0].id).toEqual(organization1Id);

    result = filterUpdateInstanceIdsFromDataContext(instancesMap, dataContextRemove);
    expect(result.length).toEqual(1);
    expect(result[0].id).toEqual(organization1Id);

    result = filterUpdateInstanceIdsFromDataContext(instancesMap, dataContextMultiple);
    expect(result.length).toEqual(2);
    expect(result.map((n) => n.id).includes(reportId)).toEqual(true);
    expect(result.map((n) => n.id).includes(organization1Id)).toEqual(true);
    expect(result.map((n) => n.id).includes(organization2Id)).toEqual(false);
  });
});
