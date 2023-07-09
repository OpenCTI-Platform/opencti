import { afterAll, describe, expect, it } from 'vitest';
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
  generateNotificationMessageForInstanceWithRefs, generateNotificationMessageForInstanceWithRefsUpdate,
  isRelationFromOrToMatchFilters
} from '../../../src/manager/notificationManager';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../src/schema/stixSightingRelationship';
import { MARKING_TLP_GREEN, MARKING_TLP_RED } from '../../../src/schema/identifier';
import { RELATION_DELIVERS } from '../../../src/schema/stixCoreRelationship';
import { STIX_TYPE_RELATION, STIX_TYPE_SIGHTING } from '../../../src/schema/general';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_UPDATE } from '../../../src/database/utils';
import { resetCacheForEntity } from '../../../src/database/cache';

// !!!!
// These tests enable to protect the notificationManager code, and especially the instance trigger notification system behavior.
// The modification of these tests should be taken with caution since the code is complex and sensitive,
// and testing cases numerous and precise.
// !!!!

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
const USER_ORGANIZATION_ADD_QUERY = gql`
    mutation UserEditionOverviewGroupAddMutation($id: ID!, $organizationId: ID!) {
        userEdit(id: $id) {
            organizationAdd(organizationId: $organizationId) {
                id
                name
                standard_id
            }
        }
    }
`;
const CREATE_LIVE_TRIGGER_QUERY = gql`
    mutation TriggerKnowledgeLiveAdd($input: TriggerLiveAddInput!) {
        triggerKnowledgeLiveAdd(input: $input) {
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

const DELETE_USER_QUERY = gql`
    mutation userDelete($id: ID!) {
        userEdit(id: $id) {
            delete
        }
    }
`;
const DELETE_GROUP_QUERY = gql`
    mutation groupDelete($id: ID!) {
        groupEdit(id: $id) {
            delete
        }
    }
`;
const DELETE_TRIGGER_QUERY = gql`
    mutation triggerDelete($id: ID!) {
        triggerDelete(id: $id)
    }
`;
const DELETE_MALWARE_QUERY = gql`
    mutation malwareDelete($id: ID!) {
        malwareEdit(id: $id) {
            delete
        }
    }
`;
const DELETE_REPORT_QUERY = gql`
    mutation reportDelete($id: ID!) {
        reportEdit(id: $id) {
            delete
        }
    }
`;
const DELETE_ORGANIZATION_QUERY = gql`
    mutation organizationDelete($id: ID!) {
        organizationEdit(id: $id) {
            delete
        }
    }
`;
const DELETE_ATTACKPATTERN_QUERY = gql`
    mutation attackPatternDelete($id: ID!) {
        attackPatternEdit(id: $id) {
            delete
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
  const redMarkingInternalId = redMarkingQueryResult?.data?.markingDefinition.id;
  // -- users --
  const context = testContext;
  const adminUser = ADMIN_USER; // admin user with all rights
  const greenUserEmail = 'greenUser@mail.com';
  const greenUserAddResult = await queryAsAdmin({ // create a restricted users with only access to green markings
    query: CREATE_USER_QUERY,
    variables: {
      input: {
        name: 'greenUser_name',
        password: 'greenuser',
        user_email: greenUserEmail,
      },
    },
  });
  const greenUserId = greenUserAddResult.data.userAdd.id;
  const greenGroupAddResult = await queryAsAdmin({ // create a group with only green marking allowed
    query: CREATE_GROUP_QUERY,
    variables: {
      input: {
        name: 'Group with green marking allowed',
        description: 'Only green marking are allowed in this group',
      }
    },
  });
  const greenGroupId = greenGroupAddResult.data.groupAdd.id;
  await queryAsAdmin({ // create the relation between the green user and the green group
    query: GROUP_RELATION_ADD_QUERY,
    variables: {
      id: greenGroupId,
      input: {
        fromId: greenUserId,
        relationship_type: 'member-of',
      },
    },
  });
  const userOrganizationAddResult = await queryAsAdmin({ // create the user organization
    query: CREATE_ORGANIZATION_QUERY,
    variables: {
      input: {
        name: 'userOrganization_name',
      },
    },
  });
  const [userOrganizationId, userOrganizationStandardId, userOrganizationName] = [
    userOrganizationAddResult.data.organizationAdd.id,
    userOrganizationAddResult.data.organizationAdd.standard_id,
    userOrganizationAddResult.data.organizationAdd.name
  ];
  await queryAsAdmin({ // create the relation between the green user and the userOrganization
    query: USER_ORGANIZATION_ADD_QUERY,
    variables: {
      id: greenUserId,
      organizationId: userOrganizationId,
    },
  });
  const greenUser = { // user belonging to userOrganization and with only access to green markings
    id: greenUserId,
    internal_id: greenUserId,
    individual_id: undefined,
    name: 'greenUser_name',
    user_email: 'user@opencti.io',
    inside_platform_organization: true,
    origin: { user_id: greenUserId },
    roles: [],
    groups: [],
    capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }],
    organizations: [],
    allowed_organizations: [{ internal_id: userOrganizationId, standard_id: userOrganizationStandardId }],
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
    let result = await generateNotificationMessageForInstanceWithRefs(context, adminUser, stixReport, [stixGreenOrganization, stixRedOrganization]);
    expect(result).toEqual('[report] report_name containing [organization] greenOrganization_name,[organization] redOrganization_name');
    result = await generateNotificationMessageForInstanceWithRefs(context, adminUser, stixReport, [stixGreenOrganization]);
    expect(result).toEqual('[report] report_name containing [organization] greenOrganization_name');
    result = await generateNotificationMessageForInstanceWithRefs(context, adminUser, stixReport, [stixGreenOrganization, stixMalware]);
    expect(result).toEqual('[report] report_name containing [organization] greenOrganization_name,[malware] malware_name');
    result = await generateNotificationMessageForInstanceWithRefs(context, adminUser, stixCoreRelationship, [stixGreenOrganization, stixMalware]);
    expect(result).toEqual('[relationship] attack-pattern_entity delivers malware_entity containing [organization] greenOrganization_name,[malware] malware_name');
    result = await generateNotificationMessageForInstanceWithRefs(context, greenUser, stixCoreRelationship, [stixGreenOrganization, stixMalware]);
    expect(result).toEqual('[relationship] Restricted delivers malware_entity containing [organization] greenOrganization_name,[malware] malware_name');

    result = await generateNotificationMessageForInstanceWithRefsUpdate(context, adminUser, stixReport, [{ instance: stixGreenOrganization, action: 'added in' }, { instance: stixRedOrganization, action: 'added in' }]);
    expect(result).toEqual('[organization] greenOrganization_name,[organization] redOrganization_name added in [report] report_name');
    result = await generateNotificationMessageForInstanceWithRefsUpdate(context, adminUser, stixReport, [{ instance: stixGreenOrganization, action: 'added in' }]);
    expect(result).toEqual('[organization] greenOrganization_name added in [report] report_name');
    result = await generateNotificationMessageForInstanceWithRefsUpdate(context, adminUser, stixReport, [{ instance: stixGreenOrganization, action: 'added in' }, { instance: stixMalware, action: 'removed from' }]);
    expect(result).toEqual('[organization] greenOrganization_name added in [report] report_name,[malware] malware_name removed from [report] report_name');
    result = await generateNotificationMessageForInstanceWithRefsUpdate(context, adminUser, stixCoreRelationship, [{ instance: stixGreenOrganization, action: 'added in' }, { instance: stixMalware, action: 'added in' }]);
    expect(result).toEqual('[organization] greenOrganization_name,[malware] malware_name added in [relationship] attack-pattern_entity delivers malware_entity');
    result = await generateNotificationMessageForInstanceWithRefsUpdate(context, greenUser, stixCoreRelationship, [{ instance: stixGreenOrganization, action: 'removed from' }, { instance: stixMalware, action: 'removed from' }]);
    expect(result).toEqual('[organization] greenOrganization_name,[malware] malware_name removed from [relationship] Restricted delivers malware_entity');
  });

  it('Should generate a notification message for an instance', async () => {
    const result = await generateNotificationMessageForInstance(context, adminUser, stixReport);
    expect(result).toEqual('[report] report_name');
  });

  it('Should generate a notification message for a relationship', async () => {
    let result = await generateNotificationMessageForInstance(context, adminUser, stixSightingRelationship);
    expect(result).toEqual('[sighting] malware_entity sighted in/at report_entity');
    result = await generateNotificationMessageForInstance(context, greenUser, stixSightingRelationship);
    expect(result).toEqual('[sighting] malware_entity sighted in/at Restricted');

    result = await generateNotificationMessageForInstance(context, adminUser, stixCoreRelationship);
    expect(result).toEqual('[relationship] attack-pattern_entity delivers malware_entity');
    result = await generateNotificationMessageForInstance(context, greenUser, stixCoreRelationship);
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
      patch: [{
        op: 'add',
        path: '/created_by_ref',
        value: redOrganizationStandardId,
      }],
      reverse_patch: [{
        op: 'remove',
        path: '/created_by_ref',
      }],
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
      }],
      reverse_patch: [{
        op: 'remove',
        path: '/created_by_ref',
      },
      {
        op: 'remove',
        path: '/granted_refs',
      }],
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
      }],
    };

    // ASSERT RESULTS
    let result = filterUpdateInstanceIdsFromUpdatePatch(instancesMap, dataContextAdd1);
    expect(result.length).toEqual(0);
    expect(result).toEqual([]);

    result = filterUpdateInstanceIdsFromUpdatePatch(instancesMap, dataContextAdd2);
    expect(result.length).toEqual(1);
    expect(result[0].instance.id).toEqual(greenOrganizationStandardId);
    expect(result[0].action).toEqual('added in');

    result = filterUpdateInstanceIdsFromUpdatePatch(instancesMap, dataContextRemove);
    expect(result.length).toEqual(1);
    expect(result[0].instance.id).toEqual(greenOrganizationStandardId);
    expect(result[0].action).toEqual('removed from');

    result = filterUpdateInstanceIdsFromUpdatePatch(instancesMap, dataContextMultiple);
    expect(result.length).toEqual(2);
    expect(result.map((n) => n.instance.id).includes(reportStandardId)).toEqual(true);
    expect(result.map((n) => n.instance.id).includes(greenOrganizationStandardId)).toEqual(true);
    expect(result.map((n) => n.instance.id).includes(redOrganizationStandardId)).toEqual(false);
  });

  it('Should build a target event for notification, these tests enable to protect the code from bad modifications', async () => {
    // -- PREPARE --
    // -- users
    const users = [adminUser, greenUser];
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
    const streamEventRemoveMalwareInRedReport = { // remove a malware in a red report
      event: EVENT_TYPE_UPDATE,
      data: {
        data: {
          ...stixRedReportWithRefs,
        },
        context: {
          patch: [{
            op: 'remove',
            path: '/object_refs',
          }],
          reverse_patch: [{
            op: 'add',
            path: '/object_refs',
            value: [malwareStandardId],
          }]
        }
      }
    };
    const streamEventRemoveMalwareInReportWithRefs = { // remove a malware in a report containing a green organization 0
      event: EVENT_TYPE_UPDATE,
      data: {
        data: {
          ...stixReport,
          object_refs: [greenOrganizationStandardId],
        },
        context: {
          patch: [{
            op: 'remove',
            path: '/object_refs',
          }],
          reverse_patch: [{
            op: 'add',
            path: '/object_refs',
            value: [malwareStandardId],
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
    const streamEventShareMalwareWithUserOrganization = { // share a malware with the user organization
      event: EVENT_TYPE_UPDATE,
      data: {
        data: {
          ...stixMalware,
          extensions: {
            [STIX_EXT_OCTI]: {
              type: ENTITY_TYPE_MALWARE,
              granted_refs: [userOrganizationStandardId],
            }
          }
        },
        context: {
          patch: [{
            op: 'add',
            path: '/granted_refs',
            value: [userOrganizationStandardId],
          }],
          reverse_patch: [{
            op: 'remove',
            path: '/granted_refs',
          }]
        }
      }
    };
    const streamEventAddRedMarkingToRelationship = { // add the red marking to a relationship
      event: EVENT_TYPE_UPDATE,
      data: {
        data: {
          ...stixCoreRelationship,
          object_marking_refs: [MARKING_TLP_RED],
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
    const streamEventAddRedMarkingAndModifyRefsInReport = { // modify 4 refs in a report :
      // add red in markings, remove green organization in author, add a malware and a red attack-pattern in object_refs
      event: EVENT_TYPE_UPDATE,
      data: {
        data: {
          ...stixReport,
          object_marking_refs: [MARKING_TLP_RED],
          object_refs: [malwareStandardId, redAttackPatternStandardId],
        },
        context: {
          patch: [{
            op: 'add',
            path: '/object_marking_refs',
            value: [MARKING_TLP_RED],
          },
          {
            op: 'remove',
            path: '/granted_refs',
          },
          {
            op: 'add',
            path: '/object_refs',
            value: [malwareStandardId, redAttackPatternStandardId],
          }
          ],
          reverse_patch: [{
            op: 'remove',
            path: '/object_marking_refs',
          },
          {
            op: 'add',
            path: '/granted_refs',
            value: [greenOrganizationStandardId],
          },
          {
            op: 'remove',
            path: '/object_refs',
          }
          ]
        }
      }
    };
    const streamEventAddRedMarkingAndAuthorInRelationship = { // add 2 refs in a relationship : red in markings, green organization in author
      event: EVENT_TYPE_UPDATE,
      data: {
        data: {
          ...stixCoreRelationship,
          object_marking_refs: [MARKING_TLP_RED],
          granted_refs: [greenOrganizationStandardId],
        },
        context: {
          patch: [{
            op: 'add',
            path: '/object_marking_refs',
            value: [MARKING_TLP_RED],
          },
          {
            op: 'add',
            path: '/granted_refs',
            value: [greenOrganizationStandardId],
          }],
          reverse_patch: [{
            op: 'remove',
            path: '/object_marking_refs',
          },
          {
            op: 'remove',
            path: '/granted_refs',
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
    const frontendFiltersRedAttackPattern = {
      elementId: [{
        id: redAttackPatternId,
        value: stixRedAttackPattern.name,
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
      },
      {
        id: userOrganizationId,
        value: userOrganizationName,
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
    const frontendFiltersMalwareAndGreenOrganization = {
      elementId: [{
        id: malwareId,
        value: stixMalware.name,
      },
      {
        id: greenOrganizationId,
        value: stixGreenOrganization.name,
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
    // -- triggers inputs
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
    const triggerRedAttackPatternAllEvents = { // instance trigger on a red attack pattern
      name: 'triggerMalwareAllEvents',
      instance_trigger: true,
      event_types: [EVENT_TYPE_UPDATE, EVENT_TYPE_DELETE],
      outcomes: [],
      filters: JSON.stringify(frontendFiltersRedAttackPattern),
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
    const triggerOrganizationsAllEvents = { // instance trigger on an organization with marking green, an organization with marking red, and the user organization
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
    const triggerMalwareAndGreenOrganizationAllEvents = { // instance trigger on a malware and a green organization
      name: 'triggerMalwareAndRedOrganizationAllEvents',
      instance_trigger: true,
      event_types: [EVENT_TYPE_UPDATE, EVENT_TYPE_DELETE],
      outcomes: [],
      filters: JSON.stringify(frontendFiltersMalwareAndGreenOrganization),
    };
    const triggerMalwareAndRedOrganizationAndRedAttackPatternAllEvents = { // instance trigger on a malware, a red organization and a red attack pattern
      name: 'triggerMalwareAndRedOrganizationAllEvents',
      instance_trigger: true,
      event_types: [EVENT_TYPE_UPDATE, EVENT_TYPE_DELETE],
      outcomes: [],
      filters: JSON.stringify(frontendFiltersMalwareAndRedOrganizationAndRedAttackPattern),
    };
    // -- create the triggers
    const triggersToCreate = [triggerRedReportAllEvents, triggerMalwareAllEvents, triggerRedOrganizationAllEvents,
      triggerOrganizationsAllEvents, triggerAttackPatternAllEvents, triggerMalwareAndRedAttackPatternAllEvents,
      triggerMalwareAndRedOrganizationAllEvents, triggerMalwareAndRedOrganizationAndRedAttackPatternAllEvents
    ];
    const triggerAddQueryPromise = triggersToCreate.map((triggerInput) => queryAsAdmin({
      query: CREATE_LIVE_TRIGGER_QUERY,
      variables: {
        input: triggerInput,
      },
    }));
    const triggerAddQueryResults = await Promise.all(triggerAddQueryPromise);
    const createdTriggerIds = triggerAddQueryResults.map((result) => result.data.triggerKnowledgeLiveAdd.id);
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
    expect(result[1].user.user_id).toEqual(greenUser.id);

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
    expect(result[1].user.user_id).toEqual(greenUser.id);

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

    // -- 07. remove a malware M in a report marked red
    // trigger on M, side events only
    result = await buildTargetEvents(context, users, streamEventRemoveMalwareInRedReport, triggerMalwareAllEvents, true);
    expect(result.length).toEqual(1);
    expect(result[0].message).toEqual('[malware] malware_name removed from [report] redReport_name');
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);

    // -- 08. remove a malware M in a report containing a green organization O
    // trigger on M, side events only
    result = await buildTargetEvents(context, users, streamEventRemoveMalwareInReportWithRefs, triggerMalwareAllEvents, true);
    expect(result.length).toEqual(2);
    expect(result[0].message).toEqual('[malware] malware_name removed from [report] report_name');
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);

    // trigger on M and O
    result = await buildTargetEvents(context, users, streamEventRemoveMalwareInReportWithRefs, triggerMalwareAndGreenOrganizationAllEvents, true);
    expect(result.length).toEqual(2);
    expect(result[0].message).toEqual('[malware] malware_name removed from [report] report_name');
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);

    // -- 09. add a red attackPattern A and a malware M in a report
    // trigger on A and M, side events only
    result = await buildTargetEvents(context, users, streamEventAddRedAttackPatternAndMalwareInReport, triggerMalwareAndRedAttackPatternAllEvents, true);
    expect(result.length).toEqual(2);
    expect(result[0].message).toEqual('[attack-pattern] redAttackPattern_name,[malware] malware_name added in [report] report_name');
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].user.user_id).toEqual(adminUser.id);
    expect(result[1].message).toEqual('[malware] malware_name added in [report] report_name');

    // -- 10. add a malware M in a report created by a red organization O and containing a red attack pattern
    // trigger on M and O
    result = await buildTargetEvents(context, users, streamEventAddMalwareInReportWithOtherRefs, triggerMalwareAndRedOrganizationAllEvents, true);
    expect(result.length).toEqual(2);
    expect(result[0].message).toEqual('[malware] malware_name added in [report] report_name');
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[1].message).toEqual('[malware] malware_name added in [report] report_name');

    // -- 11. update a report containing a malware M
    // trigger on M (no notif)
    result = await buildTargetEvents(context, users, streamEventUpdateReportContainingMalware, triggerMalwareAllEvents, true);
    expect(result).toEqual([]);

    // -- 12. update a relationship from A to M by adding a red organization O in its creators
    // trigger on O
    result = await buildTargetEvents(context, users, streamEventAddRedOrganizationInAuthorOfRelationship, triggerRedOrganizationAllEvents, true);
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].message).toEqual('[identity] redOrganization_name added in [relationship] attack-pattern_entity delivers malware_entity');

    // trigger on O and M
    result = await buildTargetEvents(context, users, streamEventAddRedOrganizationInAuthorOfRelationship, triggerMalwareAndRedOrganizationAllEvents, true);
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].message).toEqual('[identity] redOrganization_name added in [relationship] attack-pattern_entity delivers malware_entity');

    // -- 13. update a sighting from malware M to red report R, by adding a green organization O in its creators
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

    // -- 14. delete a report that contains a malware M and a red attack pattern A and that is created by a red orga O
    // trigger on M, A and O
    result = await buildTargetEvents(context, users, streamEventDeleteReportWithMultipleRefs, triggerMalwareAndRedOrganizationAndRedAttackPatternAllEvents, true);
    expect(result.length).toEqual(2);
    expect(result[0].type).toEqual(EVENT_TYPE_DELETE);
    expect(result[1].type).toEqual(EVENT_TYPE_DELETE);
    expect(result[0].message).toEqual('[report] report_name containing [identity] redOrganization_name,[malware] malware_name,[attack-pattern] redAttackPattern_name');
    expect(result[1].message).toEqual('[report] report_name containing [malware] malware_name');

    // -- 15. share a malware M with an organization
    // O is a red organization, trigger on O and M
    result = await buildTargetEvents(context, users, streamEventShareMalwareWithRedOrganization, triggerMalwareAndRedOrganizationAllEvents, true);
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].message).toEqual('[identity] redOrganization_name added in [malware] malware_name');

    // O is a green organization, trigger on O and another organization
    result = await buildTargetEvents(context, users, streamEventShareMalwareWithGreenOrganization, triggerOrganizationsAllEvents, true);
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].message).toEqual('[identity] greenOrganization_name added in [malware] malware_name');

    // 0 is an organization and the user has access to this organization, trigger on O
    result = await buildTargetEvents(context, users, streamEventShareMalwareWithUserOrganization, triggerOrganizationsAllEvents, true);
    expect(result.length).toEqual(2);
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].message).toEqual('[identity] userOrganization_name added in [malware] malware_name');
    expect(result[1].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[1].message).toEqual('[identity] userOrganization_name added in [malware] malware_name');

    // -- 16. create a report created by a red organization O
    // trigger on O
    result = await buildTargetEvents(context, users, streamEventCreateReportCreatedByRedOrganization, triggerRedOrganizationAllEvents, true);
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_CREATE);
    expect(result[0].message).toEqual('[report] report_name containing [identity] redOrganization_name');

    // -- 17. create a report created by a green organization O
    // trigger on O
    result = await buildTargetEvents(context, users, streamEventCreateReportCreatedByGreenOrganization, triggerOrganizationsAllEvents, true);
    expect(result.length).toEqual(2);
    expect(result[0].type).toEqual(EVENT_TYPE_CREATE);
    expect(result[0].message).toEqual('[report] report_name containing [identity] greenOrganization_name');
    expect(result[1].type).toEqual(EVENT_TYPE_CREATE);
    expect(result[1].message).toEqual('[report] report_name containing [identity] greenOrganization_name');

    // -- MARKINGS MODIFICATION
    // -- 18. add red marking to a relationship from red attack pattern A to malware M
    // trigger on M
    result = await buildTargetEvents(context, users, streamEventAddRedMarkingToRelationship, triggerMalwareAllEvents, true);
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_DELETE);
    expect(result[0].message).toEqual('[relationship] Restricted delivers malware_entity');
    expect(result[0].user.user_id).toEqual(greenUser.id);

    // trigger on A
    result = await buildTargetEvents(context, users, streamEventAddRedMarkingToRelationship, triggerRedAttackPatternAllEvents, true);
    expect(result.length).toEqual(0);

    // -- 19. add red marking to a report X containing a malware M
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
    expect(result[0].user.user_id).toEqual(greenUser.id);

    result = await buildTargetEvents(context, users, streamEventAddRedMarkingToReportContainingMalware, triggerReportDelete, true); // side events
    expect(result).toEqual([]);

    // trigger on M
    result = await buildTargetEvents(context, users, streamEventAddRedMarkingToReportContainingMalware, triggerMalwareAllEvents, true); // side events
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_DELETE);
    expect(result[0].message).toEqual('[report] report_name containing [malware] malware_name');
    expect(result[0].user.user_id).toEqual(greenUser.id);

    result = await buildTargetEvents(context, users, streamEventAddRedMarkingToReportContainingMalware, triggerMalwareAllEvents); // direct events
    expect(result).toEqual([]);

    // -- 20. remove the red marking from a report X
    // trigger on X, trigger event_type = update only
    result = await buildTargetEvents(context, users, streamEventRemoveRedMarkingFromReport, triggerReportUpdate); // direct events
    expect(result.length).toEqual(2);
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].message).toEqual('[report] report_name');
    expect(result[0].user.user_id).toEqual(adminUser.id);
    expect(result[1].type).toEqual(EVENT_TYPE_CREATE);
    expect(result[1].message).toEqual('[report] report_name');
    expect(result[1].user.user_id).toEqual(greenUser.id);

    // -- MODIFYING MULTIPLE REFS AND MARKINGS
    // -- 21. in a relationship from red attack-pattern A to malware M, add 2 refs:
    // -- the marking red in the markings, and green organization 0 in the author
    // trigger on M
    result = await buildTargetEvents(context, users, streamEventAddRedMarkingAndAuthorInRelationship, triggerMalwareAllEvents, true);
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_DELETE);
    expect(result[0].message).toEqual('[relationship] Restricted delivers malware_entity');
    expect(result[0].user.user_id).toEqual(greenUser.id);

    // trigger on O and another organization
    result = await buildTargetEvents(context, users, streamEventAddRedMarkingAndAuthorInRelationship, triggerOrganizationsAllEvents, true);
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].message).toEqual('[identity] greenOrganization_name added in [relationship] attack-pattern_entity delivers malware_entity');
    expect(result[0].user.user_id).toEqual(adminUser.id);

    // trigger on O and M
    result = await buildTargetEvents(context, users, streamEventAddRedMarkingAndAuthorInRelationship, triggerMalwareAndGreenOrganizationAllEvents, true);
    expect(result.length).toEqual(2);
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].message).toEqual('[identity] greenOrganization_name added in [relationship] attack-pattern_entity delivers malware_entity');
    expect(result[0].user.user_id).toEqual(adminUser.id);
    expect(result[1].type).toEqual(EVENT_TYPE_DELETE);
    expect(result[1].message).toEqual('[relationship] Restricted delivers malware_entity');
    expect(result[1].user.user_id).toEqual(greenUser.id);

    // -- 22. in a report R containing a green organization 01, modify 4 refs:
    // add the marking red in the markings, remove the green organization 01 in the author, and add a malware M and a red attack-pattern A in knowledge
    // trigger on R, delete events only, direct events
    result = await buildTargetEvents(context, users, streamEventAddRedMarkingAndModifyRefsInReport, triggerReportDelete); // direct events
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_DELETE);
    expect(result[0].message).toEqual('[report] report_name');
    expect(result[0].user.user_id).toEqual(greenUser.id);
    result = await buildTargetEvents(context, users, streamEventAddRedMarkingAndModifyRefsInReport, triggerReportDelete, true); // side events
    expect(result.length).toEqual(0);

    // trigger on R, update events only
    result = await buildTargetEvents(context, users, streamEventAddRedMarkingAndModifyRefsInReport, triggerReportUpdate); // direct events
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].message).toEqual('[report] report_name');
    expect(result[0].user.user_id).toEqual(adminUser.id);
    result = await buildTargetEvents(context, users, streamEventAddRedMarkingAndModifyRefsInReport, triggerReportUpdate, true); // side events
    expect(result.length).toEqual(0);

    // trigger on M
    result = await buildTargetEvents(context, users, streamEventAddRedMarkingAndModifyRefsInReport, triggerMalwareAllEvents, true);
    expect(result.length).toEqual(1);
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].message).toEqual('[malware] malware_name added in [report] report_name');
    expect(result[0].user.user_id).toEqual(adminUser.id);

    // trigger on O1 and 02
    result = await buildTargetEvents(context, users, streamEventAddRedMarkingAndModifyRefsInReport, triggerOrganizationsAllEvents, true);
    expect(result.length).toEqual(2);
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].message).toEqual('[identity] greenOrganization_name removed from [report] report_name');
    expect(result[0].user.user_id).toEqual(adminUser.id);
    expect(result[1].type).toEqual(EVENT_TYPE_DELETE);
    expect(result[1].message).toEqual('[report] report_name containing [identity] greenOrganization_name');
    expect(result[1].user.user_id).toEqual(greenUser.id);

    // trigger on M and O
    result = await buildTargetEvents(context, users, streamEventAddRedMarkingAndModifyRefsInReport, triggerMalwareAndGreenOrganizationAllEvents, true);
    expect(result.length).toEqual(2);
    expect(result[0].type).toEqual(EVENT_TYPE_UPDATE);
    expect(result[0].message).toEqual('[malware] malware_name added in [report] report_name,[identity] greenOrganization_name removed from [report] report_name');
    expect(result[0].user.user_id).toEqual(adminUser.id);
    expect(result[1].type).toEqual(EVENT_TYPE_DELETE);
    expect(result[1].message).toEqual('[report] report_name containing [identity] greenOrganization_name');
    expect(result[1].user.user_id).toEqual(greenUser.id);

    // -- delete created triggers --
    const triggerDeleteQueryPromises = createdTriggerIds.map((triggerId) => queryAsAdmin({
      query: DELETE_TRIGGER_QUERY,
      variables: { id: triggerId },
    }));
    await Promise.all(triggerDeleteQueryPromises);
    resetCacheForEntity(ENTITY_TYPE_RESOLVED_FILTERS);
  });
  afterAll(async () => {
    // -- delete created data (clean stream)
    await queryAsAdmin({
      query: DELETE_USER_QUERY,
      variables: { id: greenUserId },
    });
    await queryAsAdmin({
      query: DELETE_GROUP_QUERY,
      variables: { id: greenGroupId },
    });
    await queryAsAdmin({
      query: DELETE_REPORT_QUERY,
      variables: { id: reportId },
    });
    await queryAsAdmin({
      query: DELETE_REPORT_QUERY,
      variables: { id: redReportId },
    });
    await queryAsAdmin({
      query: DELETE_MALWARE_QUERY,
      variables: { id: malwareId },
    });
    await queryAsAdmin({
      query: DELETE_ATTACKPATTERN_QUERY,
      variables: { id: redAttackPatternId },
    });
    await queryAsAdmin({
      query: DELETE_ORGANIZATION_QUERY,
      variables: { id: userOrganizationId },
    });
    await queryAsAdmin({
      query: DELETE_ORGANIZATION_QUERY,
      variables: { id: greenOrganizationId },
    });
    await queryAsAdmin({
      query: DELETE_ORGANIZATION_QUERY,
      variables: { id: redOrganizationId },
    });
  });
});
