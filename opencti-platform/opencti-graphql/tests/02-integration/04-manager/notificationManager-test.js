import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin, testContext } from '../../utils/testQuery';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_RESOLVED_FILTERS
} from '../../../src/schema/stixDomainObject';
import { STIX_EXT_OCTI } from '../../../src/types/stix-extensions';
import {
  buildTargetEvents,
  filterUpdateInstanceIdsFromUpdatePatch,
  generateNotificationMessageForInstance,
  generateNotificationMessageForInstanceWithRefs,
  isRelationFromOrToMatchFilters
} from '../../../src/manager/notificationManager';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../src/schema/stixSightingRelationship';
import { generateInternalId, MARKING_TLP_GREEN, MARKING_TLP_RED } from '../../../src/schema/identifier';
import { RELATION_DELIVERS } from '../../../src/schema/stixCoreRelationship';
import { STIX_TYPE_RELATION, STIX_TYPE_SIGHTING } from '../../../src/schema/general';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_UPDATE } from '../../../src/database/utils';
import { resetCacheForEntity } from '../../../src/database/cache';

// -- PREPARE queries --
const MARKING_READ_QUERY = gql`
  query markingDefinition($id: String!) {
    markingDefinition(id: $id) {
      id
      definition_type
      definition
      standard_id
    }
  }
`;
const CREATE_USER_QUERY = gql`
    mutation UserAdd($input: UserAddInput!) {
        userAdd(input: $input) {
            id
            name
            standard_id
        }
    }
`;
const CREATE_GROUP_QUERY = gql`
    mutation GroupAdd($input: GroupAddInput!) {
        groupAdd(input: $input) {
            id
            name
        }
    }
`;
const GROUP_RELATION_ADD_QUERY = gql`
    mutation GroupEdit($id: ID!, $input: InternalRelationshipAddInput!) {
        groupEdit(id: $id) {
            relationAdd(input: $input) {
                id
                to {
                    ... on Group {
                        members {
                            edges {
                                node {
                                    id
                                }
                            }
                        }
                    }
                }
            }
        }
    }
`;
const CREATE_LIVE_TRIGGER_QUERY = gql`
    mutation TriggerLiveAdd($input: TriggerLiveAddInput!) {
        triggerLiveAdd(input: $input) {
            id
            name
        }
    }
`;
const CREATE_MALWARE_QUERY = gql`
    mutation MalwareAdd($input: MalwareAddInput!) {
        malwareAdd(input: $input) {
            id
            name
            standard_id
        }
    }
`;
const CREATE_REPORT_QUERY = gql`
    mutation ReportAdd($input: ReportAddInput!) {
        reportAdd(input: $input) {
            id
            name
            standard_id
        }
    }
`;
const CREATE_ORGANIZATION_QUERY = gql`
    mutation OrganizationAdd($input: OrganizationAddInput!) {
        organizationAdd(input: $input) {
            id
            name
            standard_id
        }
    }
`;
const CREATE_ATTACKPATTERN_QUERY = gql`
    mutation AttackPatternAdd($input: AttackPatternAddInput!) {
        attackPatternAdd(input: $input) {
            id
            name
            standard_id
        }
    }
`;
const CREATE_RELATIONSHIP_QUERY = gql`
    mutation StixCoreRelationshipAdd($input: StixCoreRelationshipAddInput!) {
        stixCoreRelationshipAdd(input: $input) {
            id
            standard_id
        }
    }
`;
const CREATE_SIGHTING_QUERY = gql`
    mutation StixSightingRelationshipAdd($input: StixSightingRelationshipAddInput!) {
        stixSightingRelationshipAdd(input: $input) {
            id
            standard_id
        }
    }
`;

describe('Notification manager behaviors test', async () => {
  // -- PREPARE --
  // -- markings --
  const greenMarkingQueryResult = await queryAsAdmin({
    query: MARKING_READ_QUERY,
    variables: { id: MARKING_TLP_GREEN }
  });
  expect(greenMarkingQueryResult).not.toBeNull();
  const [greenMarkingInternalId, greenMarkingStandardId] = [greenMarkingQueryResult?.data?.markingDefinition.id, greenMarkingQueryResult?.data?.markingDefinition.standard_id];
  const redMarkingQueryResult = await queryAsAdmin({
    query: MARKING_READ_QUERY,
    variables: { id: MARKING_TLP_RED }
  });
  expect(redMarkingQueryResult).not.toBeNull();
  const [redMarkingInternalId, redMarkingStandardId] = [redMarkingQueryResult?.data?.markingDefinition.id, redMarkingQueryResult?.data?.markingDefinition.standard_id];
  // -- users --
  const context = testContext;
  const adminUser = ADMIN_USER; // admin user with all rights
  const mail = `${generateInternalId()}@mail.com`; // TODO set a fixed email
  const loggingUserAddResult = await queryAsAdmin({ // create a restricted users with only access to green markings
    query: CREATE_USER_QUERY,
    variables: {
      input: {
        name: 'greenuser_name',
        password: 'greenuser',
        user_email: mail,
      },
    },
  });
  const loggingUserId = loggingUserAddResult.data.userAdd.id;
  const greenGroupAddResult = await queryAsAdmin({ // create a group with only green marking allowed
    query: CREATE_GROUP_QUERY,
    variables: {
      input: {
        name: 'Group with green marking allowed',
        description: 'Group of restricted user, only green marking allowed',
      }
    },
  });
  const greenGroupId = greenGroupAddResult.data.groupAdd.id;
  await queryAsAdmin({ // create the relation between the restricted user and the green group
    query: GROUP_RELATION_ADD_QUERY,
    variables: {
      id: greenGroupId,
      input: {
        fromId: loggingUserId,
        relationship_type: 'member-of',
      },
    },
  });
  const loggingUser = { // restricted user with only access to green markings
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
    allowed_marking: [{ internal_id: greenMarkingInternalId, standard_id: greenMarkingStandardId }],
    default_marking: [],
    all_marking: [],
    api_token: '',
  };
  // -- create data --
  const reportAddResult = await queryAsAdmin({
    query: CREATE_REPORT_QUERY,
    variables: {
      input: {
        name: 'report_name',
        published: '2023-06-01T22:00:00.000Z',
      },
    },
  });
  const redReportAddResult = await queryAsAdmin({
    query: CREATE_REPORT_QUERY,
    variables: {
      input: {
        name: 'redReport_name',
        published: '2023-06-01T22:00:00.000Z',
        objectMarking: [MARKING_TLP_RED, MARKING_TLP_GREEN],
      },
    },
  });
  const malwareAddResult = await queryAsAdmin({
    query: CREATE_MALWARE_QUERY,
    variables: {
      input: {
        name: 'malware_name',
      },
    },
  });
  const greenOrganizationAddResult = await queryAsAdmin({
    query: CREATE_ORGANIZATION_QUERY,
    variables: {
      input: {
        name: 'greenOrganization_name',
        objectMarking: [MARKING_TLP_GREEN],
      },
    },
  });
  const redOrganizationAddResult = await queryAsAdmin({
    query: CREATE_ORGANIZATION_QUERY,
    variables: {
      input: {
        name: 'redOrganization_name',
        objectMarking: [MARKING_TLP_RED],
      },
    },
  });
  const redAttackPatternAddResult = await queryAsAdmin({
    query: CREATE_ATTACKPATTERN_QUERY,
    variables: {
      input: {
        name: 'redAttackPattern_name',
        objectMarking: [MARKING_TLP_RED],
      },
    },
  });

  // -- fetch data ids --
  const [reportId, reportStandardId] = [reportAddResult.data.reportAdd.id, reportAddResult.data.reportAdd.standard_id];
  const [redReportId, redReportStandardId] = [redReportAddResult.data.reportAdd.id, redReportAddResult.data.reportAdd.standard_id];
  const [malwareId, malwareStandardId] = [malwareAddResult.data.malwareAdd.id, malwareAddResult.data.malwareAdd.standard_id];
  const [greenOrganizationId, greenOrganizationStandardId] = [greenOrganizationAddResult.data.organizationAdd.id, greenOrganizationAddResult.data.organizationAdd.standard_id];
  const [redOrganizationId, redOrganizationStandardId] = [redOrganizationAddResult.data.organizationAdd.id, redOrganizationAddResult.data.organizationAdd.standard_id];
  const [redAttackPatternId, redAttackPatternStandardId] = [redAttackPatternAddResult.data.attackPatternAdd.id, redAttackPatternAddResult.data.attackPatternAdd.standard_id];
  // -- create relationships --
  const relationshipAddResult = await queryAsAdmin({
    query: CREATE_RELATIONSHIP_QUERY,
    variables: {
      input: {
        fromId: redAttackPatternId,
        toId: malwareId,
        relationship_type: RELATION_DELIVERS,
      },
    },
  });
  const sightingAddResult = await queryAsAdmin({
    query: CREATE_SIGHTING_QUERY,
    variables: {
      input: {
        fromId: malwareId,
        toId: redReportId,
        attribute_count: 1,
      },
    },
  });
  const [relationshipId, relationshipStandardId] = [relationshipAddResult.data.stixCoreRelationshipAdd.id, relationshipAddResult.data.stixCoreRelationshipAdd.standard_id];
  const [sightingId, sightingStandardId] = [sightingAddResult.data.stixSightingRelationshipAdd.id, sightingAddResult.data.stixSightingRelationshipAdd.standard_id];
  // -- build stix data --
  const stixReport = {
    name: 'report_name',
    id: reportStandardId,
    type: ENTITY_TYPE_CONTAINER_REPORT,
    extensions: {
      [STIX_EXT_OCTI]: {
        id: reportId,
        type: ENTITY_TYPE_CONTAINER_REPORT
      }
    }
  };
  const stixRedReportWithRefs = {
    name: 'redReport_name',
    id: redReportStandardId,
    type: ENTITY_TYPE_CONTAINER_REPORT,
    object_label_refs: ['35-666'],
    object_marking_refs: [MARKING_TLP_RED],
    extensions: {
      [STIX_EXT_OCTI]: {
        id: redReportId,
        type: ENTITY_TYPE_CONTAINER_REPORT,
      }
    }
  };
  const stixGreenOrganization = {
    name: 'greenOrganization_name',
    id: greenOrganizationStandardId,
    type: ENTITY_TYPE_IDENTITY_ORGANIZATION,
    extensions: {
      [STIX_EXT_OCTI]: {
        type: ENTITY_TYPE_IDENTITY_ORGANIZATION
      }
    }
  };
  const stixRedOrganization = {
    name: 'redOrganization_name',
    id: redOrganizationStandardId,
    type: ENTITY_TYPE_IDENTITY_ORGANIZATION,
    extensions: {
      [STIX_EXT_OCTI]: {
        type: ENTITY_TYPE_IDENTITY_ORGANIZATION
      }
    }
  };
  const stixMalware = {
    name: 'malware_name',
    id: malwareStandardId,
    type: ENTITY_TYPE_MALWARE,
    extensions: {
      [STIX_EXT_OCTI]: {
        type: ENTITY_TYPE_MALWARE
      }
    }
  };
  const stixRedAttackPattern = {
    name: 'attack-pattern_name',
    id: redAttackPatternStandardId,
    type: ENTITY_TYPE_ATTACK_PATTERN,
    object_marking_refs: [MARKING_TLP_RED],
    extensions: {
      [STIX_EXT_OCTI]: {
        type: ENTITY_TYPE_ATTACK_PATTERN
      }
    }
  };
  const stixSightingRelationship = {
    name: 'sighting_name',
    id: sightingStandardId,
    type: STIX_TYPE_SIGHTING,
    sighting_of_ref: malwareStandardId,
    where_sighted_refs: [redReportStandardId],
    extensions: {
      [STIX_EXT_OCTI]: {
        id: sightingId,
        type: STIX_SIGHTING_RELATIONSHIP,

        sighting_of_ref_object_marking_refs: [greenMarkingInternalId],
        sighting_of_ref_granted_refs: [],
        sighting_of_type: ENTITY_TYPE_MALWARE,
        sighting_of_value: 'malware_entity',
        source_of_ref: malwareId,

        where_sighted_refs_object_marking_refs: [redMarkingInternalId],
        where_sighted_refs_granted_refs: [],
        where_sighted_types: [ENTITY_TYPE_CONTAINER_REPORT],
        where_sighted_values: ['report_entity'],
        where_sighted_refs: [redReportId],
        negative: false,
      }
    }
  };
  const stixCoreRelationship = {
    name: 'delivers relationship',
    id: relationshipStandardId,
    type: STIX_TYPE_RELATION,
    relationship_type: RELATION_DELIVERS,
    source_ref: redAttackPatternStandardId,
    target_ref: malwareStandardId,
    extensions: {
      [STIX_EXT_OCTI]: {
        id: relationshipId,
        type: RELATION_DELIVERS,

        source_ref_object_marking_refs: [redMarkingInternalId],
        source_ref_granted_refs: [],
        source_type: ENTITY_TYPE_ATTACK_PATTERN,
        source_value: 'attack-pattern_entity',
        source_ref: redAttackPatternId,

        target_ref_object_marking_refs: [greenMarkingInternalId],
        target_ref_granted_refs: [],
        target_type: ENTITY_TYPE_MALWARE,
        target_value: ['malware_entity'],
        target_ref: malwareId,
      }
    }
  };

  it('Should generate a notification message for an instance with refs', async () => {
    let result = await generateNotificationMessageForInstanceWithRefs(context, adminUser, stixReport, [stixGreenOrganization, stixRedOrganization], true);
    expect(result).toEqual('[report] report_name containing [organization] greenOrganization_name,[organization] redOrganization_name');
    result = await generateNotificationMessageForInstanceWithRefs(context, adminUser, stixReport, [stixGreenOrganization], true);
    expect(result).toEqual('[report] report_name containing [organization] greenOrganization_name');
    result = await generateNotificationMessageForInstanceWithRefs(context, adminUser, stixReport, [stixGreenOrganization, stixMalware], true);
    expect(result).toEqual('[report] report_name containing [organization] greenOrganization_name,[malware] malware_name');
    result = await generateNotificationMessageForInstanceWithRefs(context, adminUser, stixCoreRelationship, [stixGreenOrganization, stixMalware], true);
    expect(result).toEqual('[relationship] attack-pattern_entity delivers malware_entity containing [organization] greenOrganization_name,[malware] malware_name');
    result = await generateNotificationMessageForInstanceWithRefs(context, loggingUser, stixCoreRelationship, [stixGreenOrganization, stixMalware], true);
    expect(result).toEqual('[relationship] Restricted delivers malware_entity containing [organization] greenOrganization_name,[malware] malware_name');

    result = await generateNotificationMessageForInstanceWithRefs(context, adminUser, stixReport, [stixGreenOrganization, stixRedOrganization], false);
    expect(result).toEqual('[organization] greenOrganization_name,[organization] redOrganization_name in [report] report_name');
    result = await generateNotificationMessageForInstanceWithRefs(context, adminUser, stixReport, [stixGreenOrganization], false);
    expect(result).toEqual('[organization] greenOrganization_name in [report] report_name');
    result = await generateNotificationMessageForInstanceWithRefs(context, adminUser, stixReport, [stixGreenOrganization, stixMalware], false);
    expect(result).toEqual('[organization] greenOrganization_name,[malware] malware_name in [report] report_name');
    result = await generateNotificationMessageForInstanceWithRefs(context, adminUser, stixCoreRelationship, [stixGreenOrganization, stixMalware], false);
    expect(result).toEqual('[organization] greenOrganization_name,[malware] malware_name in [relationship] attack-pattern_entity delivers malware_entity');
    result = await generateNotificationMessageForInstanceWithRefs(context, loggingUser, stixCoreRelationship, [stixGreenOrganization, stixMalware], false);
    expect(result).toEqual('[organization] greenOrganization_name,[malware] malware_name in [relationship] Restricted delivers malware_entity');
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

    instancesMap.set(stixGreenOrganization.id, stixGreenOrganization);
    result = isRelationFromOrToMatchFilters(instancesMap, stixCoreRelationship);
    expect(result).toEqual(false);
    result = isRelationFromOrToMatchFilters(instancesMap, stixSightingRelationship);
    expect(result).toEqual(false);

    instancesMap.set(malwareStandardId, stixMalware);
    result = isRelationFromOrToMatchFilters(instancesMap, stixCoreRelationship);
    expect(result).toEqual(true);
    result = isRelationFromOrToMatchFilters(instancesMap, stixSightingRelationship);
    expect(result).toEqual(true);
  });

  it('Should return the instances that are in the update patch and in the instances map', async () => {
    // -- PREPARE --
    const instancesMap = new Map([[stixGreenOrganization.id, stixGreenOrganization], [stixReport.id, stixReport]]);
    const dataContextAdd1 = {
      patch: [
        {
          op: 'add',
          path: '/created_by_ref',
          value: redOrganizationStandardId,
        }
      ],
      reverse_patch: [
        {
          op: 'remove',
          path: '/created_by_ref',
        }
      ],
    };
    const dataContextAdd2 = {
      patch: [{
        op: 'add',
        path: '/created_by_ref',
        value: greenOrganizationStandardId,
      },
      {
        op: 'add',
        path: '/granted_refs',
        value: redOrganizationStandardId,
      }
      ],
      reverse_patch: [
        {
          op: 'remove',
          path: '/created_by_ref',
        }
      ],
    };
    const dataContextRemove = {
      patch: [{
        op: 'remove',
        path: '/created_by_ref',
      }],
      reverse_patch: [{
        op: 'add',
        path: '/created_by_ref',
        value: greenOrganizationStandardId,
      }],
    };
    const dataContextMultiple = {
      patch: [{
        op: 'add',
        path: '/created_by_ref',
        value: greenOrganizationStandardId,
      }],
      reverse_patch: [{
        op: 'add',
        path: '/granted_refs',
        value: redOrganizationStandardId,
      },
      {
        op: 'add',
        path: '/granted_refs',
        value: reportStandardId,
      },
      ],
    };

    // ASSERT RESULTS
    let result = filterUpdateInstanceIdsFromUpdatePatch(instancesMap, dataContextAdd1);
    expect(result.length).toEqual(0);
    expect(result).toEqual([]);

    result = filterUpdateInstanceIdsFromUpdatePatch(instancesMap, dataContextAdd2);
    expect(result.length).toEqual(1);
    expect(result[0].id).toEqual(greenOrganizationStandardId);

    result = filterUpdateInstanceIdsFromUpdatePatch(instancesMap, dataContextRemove);
    expect(result.length).toEqual(1);
    expect(result[0].id).toEqual(greenOrganizationStandardId);

    result = filterUpdateInstanceIdsFromUpdatePatch(instancesMap, dataContextMultiple);
    expect(result.length).toEqual(2);
    expect(result.map((n) => n.id).includes(reportStandardId)).toEqual(true);
    expect(result.map((n) => n.id).includes(greenOrganizationStandardId)).toEqual(true);
    expect(result.map((n) => n.id).includes(redOrganizationStandardId)).toEqual(false);
  });

  it('Should build a target event for notification, these tests enable to protect the code from bad modifications', async () => {
    // -- PREPARE --
    // -- users
    const users = [adminUser, loggingUser];
    // -- stream events
    const streamEventDeleteReport = { // delete a report
      event: EVENT_TYPE_DELETE,
      data: {
        data: stixRedReportWithRefs,
      }
    };
    const streamEventUpdateReport = { // update a report
      event: EVENT_TYPE_UPDATE,
      data: {
        data: stixRedReportWithRefs,
        context: {
          patch: [{
            op: 'add',
            path: '/labels',
            value: ['35-666'],
          }],
          reverse_patch: [{
            op: 'remove',
            path: '/labels',
          }]
        }
      }
    };
    const streamEventUpdateReportContainingMalware = { // update a report containing a malware
      event: EVENT_TYPE_UPDATE,
      data: {
        data: {
          ...stixRedReportWithRefs,
          object_refs: [malwareStandardId],
        },
        context: {
          patch: [{
            op: 'add',
            path: '/labels',
            value: ['35-666'],
          }],
          reverse_patch: [{
            op: 'remove',
            path: '/labels',
          }]
        }
      }
    };
    const streamEventCreateRelationship = { // create a relationship from a red attack pattern to a green malware
      event: EVENT_TYPE_CREATE,
      data: {
        data: stixCoreRelationship,
      }
    };
    const streamEventCreateSighting = { // create a sighting from a green malware to a red report
      event: EVENT_TYPE_CREATE,
      data: {
        data: stixSightingRelationship,
      }
    };
    const streamEventUpdateRelationship = { // update a relationship from red attack pattern to green malware
      event: EVENT_TYPE_UPDATE,
      data: {
        data: stixCoreRelationship,
        context: {
          patch: [{
            op: 'add',
            path: '/labels',
            value: ['35-666'],
          }],
          reverse_patch: [{
            op: 'remove',
            path: '/labels',
          }]
        }
      }
    };
    const streamEventAddMalwareInRedReport = { // add a malware in a red report
      event: EVENT_TYPE_UPDATE,
      data: {
        data: {
          ...stixRedReportWithRefs,
          object_refs: [malwareStandardId],
        },
        context: {
          patch: [{
            op: 'add',
            path: '/object_refs',
            value: [malwareStandardId],
          }],
          reverse_patch: [{
            op: 'remove',
            path: '/object_refs',
          }]
        }
      }
    };
    const streamEventAddRedAttackPatternAndMalwareInReport = { // add a red attack pattern and a malware in a report
      event: EVENT_TYPE_UPDATE,
      data: {
        data: {
          ...stixReport,
          object_refs: [redAttackPatternStandardId, malwareStandardId],
        },
        context: {
          patch: [{
            op: 'add',
            path: '/object_refs',
            value: [redAttackPatternStandardId, malwareStandardId],
          }],
          reverse_patch: [{
            op: 'remove',
            path: '/object_refs',
          }]
        }
      }
    };
    const streamEventAddMalwareInReportWithOtherRefs = { // add a malware in a report created by a red organization and containing an attack pattern
      event: EVENT_TYPE_UPDATE,
      data: {
        data: {
          ...stixReport,
          object_refs: [redAttackPatternStandardId, malwareStandardId],
          created_by_ref: [redOrganizationStandardId]
        },
        context: {
          patch: [{
            op: 'add',
            path: '/object_refs',
            value: [malwareStandardId],
          }],
          reverse_patch: [{
            op: 'remove',
            path: '/object_refs',
          }]
        }
      }
    };
    const streamEventAddRedOrganizationInAuthorOfRelationship = { // add a red organization as Author of a relationship
      event: EVENT_TYPE_UPDATE,
      data: {
        data: {
          ...stixCoreRelationship,
          created_by_ref: [redOrganizationStandardId]
        },
        context: {
          patch: [{
            op: 'add',
            path: '/created_by_ref',
            value: [redOrganizationStandardId],
          }],
          reverse_patch: [{
            op: 'remove',
            path: '/created_by_ref',
          }]
        }
      }
    };
    const streamEventAddGreenOrganizationInAuthorOfSighting = { // add a green organization as Author of a sighting
      event: EVENT_TYPE_UPDATE,
      data: {
        data: {
          ...stixSightingRelationship,
          created_by_ref: [greenOrganizationStandardId]
        },
        context: {
          patch: [{
            op: 'add',
            path: '/created_by_ref',
            value: [greenOrganizationStandardId],
          }],
          reverse_patch: [{
            op: 'remove',
            path: '/created_by_ref',
          }]
        }
      }
    };
    const streamEventDeleteReportWithMultipleRefs = { // delete a report containing a malware and a red attack pattern, and created by a red organization
      event: EVENT_TYPE_DELETE,
      data: {
        data: {
          ...stixReport,
          created_by_ref: [redOrganizationStandardId],
          object_refs: [malwareStandardId, redAttackPatternStandardId],
        },
      }
    };
    const streamEventCreateReportCreatedByRedOrganization = { // create a report with a red organization in its creators
      event: EVENT_TYPE_CREATE,
      data: {
        data: {
          ...stixReport,
          created_by_ref: [redOrganizationStandardId],
        },
      }
    };
    const streamEventCreateReportCreatedByGreenOrganization = { // create a report with a green organization in its creators
      event: EVENT_TYPE_CREATE,
      data: {
        data: {
          ...stixReport,
          created_by_ref: [greenOrganizationStandardId],
        },
      }
    };
    const streamEventShareMalwareWithRedOrganization = { // share a malware with a red organization
      event: EVENT_TYPE_UPDATE,
      data: {
        data: {
          ...stixMalware,
          extensions: {
            [STIX_EXT_OCTI]: {
              type: ENTITY_TYPE_MALWARE,
              granted_refs: [redOrganizationStandardId],
            }
          }
        },
        context: {
          patch: [{
            op: 'add',
            path: '/granted_refs',
            value: [redOrganizationStandardId],
          }],
          reverse_patch: [{
            op: 'remove',
            path: '/granted_refs',
          }]
        }
      }
    };
    const streamEventShareMalwareWithGreenOrganization = { // share a malware with a green organization
      event: EVENT_TYPE_UPDATE,
      data: {
        data: {
          ...stixMalware,
          extensions: {
            [STIX_EXT_OCTI]: {
              type: ENTITY_TYPE_MALWARE,
              granted_refs: [greenOrganizationStandardId],
            }
          }
        },
        context: {
          patch: [{
            op: 'add',
            path: '/granted_refs',
            value: [greenOrganizationStandardId],
          }],
          reverse_patch: [{
            op: 'remove',
            path: '/granted_refs',
          }]
        }
      }
    };
    const streamEventRemoveRedMarkingFromReport = { // remove the red marking from a report
      event: EVENT_TYPE_UPDATE,
      data: {
        data: {
          ...stixReport,
        },
        context: {
          patch: [{
            op: 'remove',
            path: '/object_marking_refs',
          }],
          reverse_patch: [{
            op: 'add',
            path: '/object_marking_refs',
            value: [MARKING_TLP_RED],
          }]
        }
      }
    };
    const streamEventAddRedMarkingToReportContainingMalware = { // add the red marking to a report that contains a malware
      event: EVENT_TYPE_UPDATE,
      data: {
        data: {
          ...stixReport,
          object_marking_refs: [MARKING_TLP_RED],
          object_refs: [malwareStandardId],
        },
        context: {
          patch: [{
            op: 'add',
            path: '/object_marking_refs',
            value: [MARKING_TLP_RED],
          }],
          reverse_patch: [{
            op: 'remove',
            path: '/object_marking_refs',
          }]
        }
      }
    };
    // -- frontend filters
    const frontendFiltersReport = {
      elementId: [{
        id: reportId,
        value: stixReport.name,
      }]
    };
    const frontendFiltersRedReport = {
      elementId: [{
        id: redReportId,
        value: stixRedReportWithRefs.name,
      }]
    };
    const frontendFiltersMalware = {
      elementId: [{
        id: malwareId,
        value: stixMalware.name,
      }]
    };
    const frontendFiltersRedOrganization = {
      elementId: [{
        id: redOrganizationId,
        value: stixRedOrganization.name,
      }]
    };
    const frontendFiltersOrganizations = {
      elementId: [{
        id: redOrganizationId,
        value: stixRedOrganization.name,
      },
      {
        id: greenOrganizationId,
        value: stixGreenOrganization.name,
      }]
    };
    const frontendFiltersAttackPattern = {
      elementId: [{
        id: redAttackPatternId,
        value: stixRedAttackPattern.name,
      }]
    };
    const frontendFiltersMalwareAndRedAttackPattern = {
      elementId: [{
        id: malwareId,
        value: stixMalware.name,
      },
      {
        id: redAttackPatternId,
        value: stixRedAttackPattern.name,
      }
      ]
    };
    const frontendFiltersMalwareAndRedOrganization = {
      elementId: [{
        id: malwareId,
        value: stixMalware.name,
      },
      {
        id: redOrganizationId,
        value: stixRedOrganization.name,
      }
      ]
    };
    const frontendFiltersMalwareAndRedOrganizationAndRedAttackPattern = {
      elementId: [{
        id: malwareId,
        value: stixMalware.name,
      },
      {
        id: redOrganizationId,
        value: stixRedOrganization.name,
      },
      {
        id: redAttackPatternId,
        value: stixRedAttackPattern.name,
      }
      ]
    };
    // -- build triggers inputs
    const triggerReportUpdate = { // instance trigger on a report, update only
      name: 'triggerReportUpdate',
      instance_trigger: true,
      event_types: [EVENT_TYPE_UPDATE],
      outcomes: ['UI'],
      filters: JSON.stringify(frontendFiltersReport),
    };
    const triggerReportDelete = { // instance trigger on a report, deletion only
      instance_trigger: true,
      event_types: [EVENT_TYPE_DELETE],
      outcomes: ['UI'],
      filters: JSON.stringify(frontendFiltersReport),
    };
    const triggerRedReportUpdate = { // instance trigger on a red report update
      instance_trigger: true,
      event_types: [EVENT_TYPE_UPDATE],
      outcomes: [],
      filters: JSON.stringify(frontendFiltersRedReport),
    };
    const triggerRedReportAllEvents = { // instance trigger on a red report
      name: 'triggerRedReportAllEvents',
      instance_trigger: true,
      event_types: [EVENT_TYPE_UPDATE, EVENT_TYPE_DELETE],
      outcomes: [],
      filters: JSON.stringify(frontendFiltersRedReport),
    };
    const triggerMalwareAllEvents = { // instance trigger on a malware
      name: 'triggerMalwareAllEvents',
      instance_trigger: true,
      event_types: [EVENT_TYPE_UPDATE, EVENT_TYPE_DELETE],
      outcomes: [],
      filters: JSON.stringify(frontendFiltersMalware),
    };
    const triggerMalwareUpdate = { // instance trigger on a malware, update only
      name: 'triggerMalwareAllEvents',
      instance_trigger: true,
      event_types: [EVENT_TYPE_UPDATE],
      outcomes: [],
      filters: JSON.stringify(frontendFiltersMalware),
    };
    const triggerMalwareDelete = { // instance trigger on a malware, delete only
      name: 'triggerMalwareAllEvents',
      instance_trigger: true,
      event_types: [EVENT_TYPE_DELETE],
      outcomes: [],
      filters: JSON.stringify(frontendFiltersMalware),
    };
    const triggerRedOrganizationAllEvents = { // instance trigger on an organization with marking red
      name: 'triggerRedOrganizationAllEvents',
      instance_trigger: true,
      event_types: [EVENT_TYPE_UPDATE, EVENT_TYPE_DELETE],
      outcomes: [],
      filters: JSON.stringify(frontendFiltersRedOrganization),
    };
    const triggerOrganizationsAllEvents = { // instance trigger on an organization with marking green and an organization with marking red
      name: 'triggerOrganizationsAllEvents',
      instance_trigger: true,
      event_types: [EVENT_TYPE_UPDATE, EVENT_TYPE_DELETE],
      outcomes: [],
      filters: JSON.stringify(frontendFiltersOrganizations),
    };
    const triggerAttackPatternAllEvents = { // instance trigger on a red attack pattern
      name: 'triggerAttackPatternAllEvents',
      instance_trigger: true,
      event_types: [EVENT_TYPE_UPDATE, EVENT_TYPE_DELETE],
      outcomes: [],
      filters: JSON.stringify(frontendFiltersAttackPattern),
    };
    const triggerMalwareAndRedAttackPatternAllEvents = { // instance trigger on a malware and a red attack pattern
      name: 'triggerMalwareAndRedAttackPatternAllEvents',
      instance_trigger: true,
      event_types: [EVENT_TYPE_UPDATE, EVENT_TYPE_DELETE],
      outcomes: [],
      filters: JSON.stringify(frontendFiltersMalwareAndRedAttackPattern),
    };
    const triggerMalwareAndRedOrganizationAllEvents = { // instance trigger on a malware and a red organization
      name: 'triggerMalwareAndRedOrganizationAllEvents',
      instance_trigger: true,
      event_types: [EVENT_TYPE_UPDATE, EVENT_TYPE_DELETE],
      outcomes: [],
      filters: JSON.stringify(frontendFiltersMalwareAndRedOrganization),
    };
    const triggerMalwareAndRedOrganizationAndRedAttackPatternAllEvents = { // instance trigger on a malware, a red organization and a red attack pattern
      name: 'triggerMalwareAndRedOrganizationAllEvents',
      instance_trigger: true,
      event_types: [EVENT_TYPE_UPDATE, EVENT_TYPE_DELETE],
      outcomes: [],
      filters: JSON.stringify(frontendFiltersMalwareAndRedOrganizationAndRedAttackPattern),
    };
    // -- create the triggers
    await queryAsAdmin({
      query: CREATE_LIVE_TRIGGER_QUERY,
      variables: {
        input: triggerRedReportUpdate,
      },
    });
    await queryAsAdmin({
      query: CREATE_LIVE_TRIGGER_QUERY,
      variables: {
        input: triggerRedReportAllEvents,
      },
    });
    await queryAsAdmin({
      query: CREATE_LIVE_TRIGGER_QUERY,
      variables: {
        input: triggerMalwareAllEvents,
      },
    });
    await queryAsAdmin({
      query: CREATE_LIVE_TRIGGER_QUERY,
      variables: {
        input: triggerRedOrganizationAllEvents,
      },
    });
    await queryAsAdmin({
      query: CREATE_LIVE_TRIGGER_QUERY,
      variables: {
        input: triggerOrganizationsAllEvents,
      },
    });
    await queryAsAdmin({
      query: CREATE_LIVE_TRIGGER_QUERY,
      variables: {
        input: triggerAttackPatternAllEvents,
      },
    });
    await queryAsAdmin({
      query: CREATE_LIVE_TRIGGER_QUERY,
      variables: {
        input: triggerMalwareAndRedAttackPatternAllEvents,
      },
    });
    await queryAsAdmin({
      query: CREATE_LIVE_TRIGGER_QUERY,
      variables: {
        input: triggerMalwareAndRedOrganizationAllEvents,
      },
    });
    await queryAsAdmin({
      query: CREATE_LIVE_TRIGGER_QUERY,
      variables: {
        input: triggerMalwareAndRedOrganizationAndRedAttackPatternAllEvents,
      },
    });
    resetCacheForEntity(ENTITY_TYPE_RESOLVED_FILTERS);

    // -- TESTS -- //
    // -- SIMPLE CASES --
    // -- 01. delete a report X marked red
    // trigger on update of X, direct events only
    let result = await buildTargetEvents(context, users, streamEventDeleteReport, triggerRedReportUpdate, false);
    expect(result).toEqual([]);

    // trigger on all events for X, direct events only
    result = await buildTargetEvents(context, users, streamEventDeleteReport, triggerRedReportAllEvents, false);
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_DELETE);
    expect(result[0].message).toEqual('[report] redReport_name');
    expect(result[0].user.outcomes).toEqual([]);
    expect(result[0].user.user_id).toEqual(adminUser.id);

    // trigger on all events for X, side events only
    result = await buildTargetEvents(context, users, streamEventDeleteReport, triggerRedReportAllEvents, true);
    expect(result).toEqual([]);

    // -- 02. update the description of a report X marked red
    // trigger on all events for X, direct events
    result = await buildTargetEvents(context, users, streamEventUpdateReport, triggerRedReportAllEvents, false);
    expect(result.length).toEqual(1);
    expect(result[0].message).toEqual('[report] redReport_name');
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);

    // -- RELATIONSHIPS --
    // -- 03. create a relationship from attack pattern A marked red to malware M
    // trigger on M, side events only
    result = await buildTargetEvents(context, users, streamEventCreateRelationship, triggerMalwareAllEvents, true);
    expect(result.length).toEqual(2);
    expect(result[0].message).toEqual('[relationship] attack-pattern_entity delivers malware_entity');
    expect(result[0].type).toEqual(EVENT_TYPE_CREATE);
    expect(result[0].user.outcomes).toEqual([]);
    expect(result[0].user.user_id).toEqual(adminUser.id);
    expect(result[1].type).toEqual(EVENT_TYPE_CREATE);
    expect(result[1].message).toEqual('[relationship] Restricted delivers malware_entity');
    expect(result[1].user.user_id).toEqual(loggingUser.id);

    // trigger on A and M, side events only
    result = await buildTargetEvents(context, users, streamEventCreateRelationship, triggerMalwareAndRedAttackPatternAllEvents, true);
    expect(result.length).toEqual(2);
    expect(result[0].message).toEqual('[relationship] attack-pattern_entity delivers malware_entity');
    expect(result[0].type).toEqual(EVENT_TYPE_CREATE);
    expect(result[0].user.outcomes).toEqual([]);
    expect(result[1].message).toEqual('[relationship] Restricted delivers malware_entity');

    // trigger on A, side events only
    result = await buildTargetEvents(context, users, streamEventCreateRelationship, triggerAttackPatternAllEvents, true);
    expect(result.length).toEqual(1);
    expect(result[0].message).toEqual('[relationship] attack-pattern_entity delivers malware_entity');

    // -- 04. create a sighting from a green malware M to a red report R
    // trigger on M, side events only
    result = await buildTargetEvents(context, users, streamEventCreateSighting, triggerMalwareAllEvents, true);
    expect(result.length).toEqual(2);
    expect(result[0].message).toEqual('[sighting] malware_entity sighted in/at report_entity');
    expect(result[0].type).toEqual(EVENT_TYPE_CREATE);
    expect(result[0].user.user_id).toEqual(adminUser.id);
    expect(result[1].type).toEqual(EVENT_TYPE_CREATE);
    expect(result[1].message).toEqual('[sighting] malware_entity sighted in/at Restricted');
    expect(result[1].user.user_id).toEqual(loggingUser.id);

    // trigger on M, delete event only, side events only
    result = await buildTargetEvents(context, users, streamEventCreateSighting, triggerMalwareDelete, true);
    expect(result.length).toEqual(0);

    // trigger on M, delete event only, side events only
    result = await buildTargetEvents(context, users, streamEventCreateSighting, triggerMalwareUpdate, true);
    expect(result.length).toEqual(2);
    expect(result[0].message).toEqual('[sighting] malware_entity sighted in/at report_entity');
    expect(result[0].type).toEqual(EVENT_TYPE_CREATE);

    // trigger on R, side events only
    result = await buildTargetEvents(context, users, streamEventCreateSighting, triggerRedReportAllEvents, true);
    expect(result.length).toEqual(1);
    expect(result[0].message).toEqual('[sighting] malware_entity sighted in/at report_entity');
    expect(result[0].type).toEqual(EVENT_TYPE_CREATE);
    expect(result[0].user.user_id).toEqual(adminUser.id);

    // -- 05. update a relationship from Y marked red to X
    // trigger on X, side events only (no notif)
    result = await buildTargetEvents(context, users, streamEventUpdateRelationship, triggerMalwareAllEvents, true);
    expect(result.length).toEqual(0);

    // -- REFS --
    // -- 06. add a malware M in a report marked red
    // trigger on M, side events only
    result = await buildTargetEvents(context, users, streamEventAddMalwareInRedReport, triggerMalwareAllEvents, true);
    expect(result.length).toEqual(1);
    expect(result[0].message).toEqual('[malware] malware_name added in [report] redReport_name');
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);

    // -- 07. add a red attackPattern A and a malware M in a report
    // trigger on A and M, side events only
    result = await buildTargetEvents(context, users, streamEventAddRedAttackPatternAndMalwareInReport, triggerMalwareAndRedAttackPatternAllEvents, true);
    expect(result.length).toEqual(2);
    expect(result[0].message).toEqual('[attack-pattern] redAttackPattern_name,[malware] malware_name added in [report] report_name');
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].user.user_id).toEqual(adminUser.id);
    expect(result[1].message).toEqual('[malware] malware_name added in [report] report_name');

    // -- 08. add a malware M in a report created by a red organization O and containing a red attack pattern
    // trigger on M and O
    result = await buildTargetEvents(context, users, streamEventAddMalwareInReportWithOtherRefs, triggerMalwareAndRedOrganizationAllEvents, true);
    expect(result.length).toEqual(2);
    expect(result[0].message).toEqual('[malware] malware_name in [report] report_name');
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[1].message).toEqual('[malware] malware_name added in [report] report_name');

    // -- 09. update a report containing a malware M
    // trigger on M (no notif)
    result = await buildTargetEvents(context, users, streamEventUpdateReportContainingMalware, triggerMalwareAllEvents, true);
    expect(result).toEqual([]);

    // -- 10. update a relationship from A to M by adding a red organization O in its creators
    // trigger on O
    result = await buildTargetEvents(context, users, streamEventAddRedOrganizationInAuthorOfRelationship, triggerRedOrganizationAllEvents, true);
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].message).toEqual('[identity] redOrganization_name added in [relationship] attack-pattern_entity delivers malware_entity');

    // trigger on O and M
    result = await buildTargetEvents(context, users, streamEventAddRedOrganizationInAuthorOfRelationship, triggerMalwareAndRedOrganizationAllEvents, true);
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].message).toEqual('[identity] redOrganization_name in [relationship] attack-pattern_entity delivers malware_entity');

    // -- 07. update a sighting from malware M to red report R, by adding a green organization O in its creators
    // trigger on M
    result = await buildTargetEvents(context, users, streamEventAddGreenOrganizationInAuthorOfSighting, triggerMalwareAllEvents, true);
    expect(result.length).toEqual(0);

    // trigger on O and a red organization
    result = await buildTargetEvents(context, users, streamEventAddGreenOrganizationInAuthorOfSighting, triggerOrganizationsAllEvents, true);
    expect(result.length).toEqual(2);
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].message).toEqual('[identity] greenOrganization_name added in [sighting] malware_entity sighted in/at report_entity');
    expect(result[0].user.user_id).toEqual(adminUser.id);
    expect(result[1].message).toEqual('[identity] greenOrganization_name added in [sighting] malware_entity sighted in/at Restricted');

    // TODO share a malware with an orga, user has access to this orga
    // TODO mark a relationship as red

    // -- 8. delete a report that contains a malware M and a red attack pattern A and that is created by a red orga O
    // trigger on M, A and O
    result = await buildTargetEvents(context, users, streamEventDeleteReportWithMultipleRefs, triggerMalwareAndRedOrganizationAndRedAttackPatternAllEvents, true);
    expect(result.length).toEqual(2);
    expect(result[0].type).toEqual(EVENT_TYPE_DELETE);
    expect(result[1].type).toEqual(EVENT_TYPE_DELETE);
    expect(result[0].message).toEqual('[report] report_name containing [identity] redOrganization_name,[malware] malware_name,[attack-pattern] redAttackPattern_name');
    expect(result[1].message).toEqual('[report] report_name containing [malware] malware_name');

    // -- 9. share a malware M with an organization
    // O is a red organization, trigger on O and M
    result = await buildTargetEvents(context, users, streamEventShareMalwareWithRedOrganization, triggerMalwareAndRedOrganizationAllEvents, true);
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].message).toEqual('[identity] redOrganization_name in [malware] malware_name');

    // O is a green organization, trigger on O and another organization
    result = await buildTargetEvents(context, users, streamEventShareMalwareWithGreenOrganization, triggerOrganizationsAllEvents, true);
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].message).toEqual('[identity] greenOrganization_name in [malware] malware_name');

    // -- 10. create a report created by a red organization O
    // trigger on O
    result = await buildTargetEvents(context, users, streamEventCreateReportCreatedByRedOrganization, triggerRedOrganizationAllEvents, true);
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_CREATE);
    expect(result[0].message).toEqual('[report] report_name containing [identity] redOrganization_name');

    // -- 11. create a report created by a green organization O
    // trigger on O
    result = await buildTargetEvents(context, users, streamEventCreateReportCreatedByGreenOrganization, triggerOrganizationsAllEvents, true);
    expect(result.length).toEqual(2);
    expect(result[0].type).toEqual(EVENT_TYPE_CREATE);
    expect(result[0].message).toEqual('[report] report_name containing [identity] greenOrganization_name');
    expect(result[1].type).toEqual(EVENT_TYPE_CREATE);
    expect(result[1].message).toEqual('[report] report_name containing [identity] greenOrganization_name');

    // -- MARKINGS MODIFICATION
    // -- 11. add red marking to a report X containing a malware M
    // trigger on X, trigger event_type = update only
    result = await buildTargetEvents(context, users, streamEventAddRedMarkingToReportContainingMalware, triggerReportUpdate); // direct events
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].message).toEqual('[report] report_name');
    expect(result[0].user.outcomes).toEqual(['UI']);
    expect(result[0].user.user_id).toEqual(adminUser.id);

    result = await buildTargetEvents(context, users, streamEventAddRedMarkingToReportContainingMalware, triggerReportUpdate, true); // side events
    expect(result.length).toEqual(0);

    // trigger on X, trigger event_type = delete only
    result = await buildTargetEvents(context, users, streamEventAddRedMarkingToReportContainingMalware, triggerReportDelete); // direct events
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_DELETE);
    expect(result[0].message).toEqual('[report] report_name');
    expect(result[0].user.user_id).toEqual(loggingUser.id);

    result = await buildTargetEvents(context, users, streamEventAddRedMarkingToReportContainingMalware, triggerReportDelete, true); // side events
    expect(result).toEqual([]);

    // trigger on M
    result = await buildTargetEvents(context, users, streamEventAddRedMarkingToReportContainingMalware, triggerMalwareAllEvents, true); // side events
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_DELETE);
    expect(result[0].message).toEqual('[report] report_name containing [malware] malware_name');
    expect(result[0].user.user_id).toEqual(loggingUser.id);

    result = await buildTargetEvents(context, users, streamEventAddRedMarkingToReportContainingMalware, triggerMalwareAllEvents); // direct events
    expect(result).toEqual([]);

    // -- 12. remove the red marking from a report X
    // trigger on X, trigger event_type = update only
    result = await buildTargetEvents(context, users, streamEventRemoveRedMarkingFromReport, triggerReportUpdate); // direct events
    expect(result.length).toEqual(2);
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].message).toEqual('[report] report_name');
    expect(result[0].user.user_id).toEqual(adminUser.id);
    expect(result[1].type).toEqual(EVENT_TYPE_CREATE);
    expect(result[1].message).toEqual('[report] report_name');
    expect(result[1].user.user_id).toEqual(loggingUser.id);
  });
});
