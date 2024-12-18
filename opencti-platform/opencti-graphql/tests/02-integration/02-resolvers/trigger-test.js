import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, AMBER_GROUP, editorQuery, queryAsAdmin, securityQuery, USER_EDITOR, USER_SECURITY } from '../../utils/testQuery';
import { EVENT_TYPE_CREATE } from '../../../src/database/utils';
import { queryAsUserIsExpectedForbidden } from '../../utils/testQueryHelper';

const LIST_TRIGGERS_KNOWLEDGE_QUERY = gql`
    query triggersKnowledge(
        $search: String
        $filters: FilterGroup
        $includeAuthorities: Boolean
    ) {
        triggersKnowledge(search: $search, filters: $filters, includeAuthorities: $includeAuthorities) {
            edges {
                node {
                    id
                    name
                    trigger_type
                    event_types
                    description
                    created
                    modified
                    notifiers {
                      id
                      name
                    }
                }
            }
        }
    }
`;

const READ_TRIGGER_KNOWLEDGE_QUERY = gql`
    query trigger($id: String!) {
        triggerKnowledge(id: $id) {
            id
            name
        }
    }
`;

const CREATE_TRIGGER_KNOWLEDGE_LIVE_QUERY = gql`
    mutation TriggerKnowledgeLiveAdd($input: TriggerLiveAddInput!) {
        triggerKnowledgeLiveAdd(input: $input) {
            id
            name
        }
    }
`;

const CREATE_TRIGGER_KNOWLEDGE_DIGEST_QUERY = gql`
    mutation TriggerKnowledgeDigestAdd($input: TriggerDigestAddInput!) {
        triggerKnowledgeDigestAdd(input: $input) {
            id
            name
        }
    }
`;

const UPDATE_TRIGGER_KNOWLEDGE_QUERY = gql`
    mutation TriggerKnowledgeEdit($id: ID!, $input: [EditInput!]!) {
        triggerKnowledgeFieldPatch(id: $id, input: $input) {
            id
            name
        }
    }
`;

const DELETE_TRIGGER_KNOWLEDGE_QUERY = gql`
    mutation triggerKnowledgeDelete($id: ID!) {
        triggerKnowledgeDelete(id: $id)
    }
`;

// region trigger activity
const CREATE_TRIGGER_ACTIVITY_LIVE_QUERY = gql`
  mutation TriggerActivityLiveAdd($input: TriggerActivityLiveAddInput!) {
    triggerActivityLiveAdd(input: $input) {
      id
      name
    }
  }
`;
const CREATE_TRIGGER_ACTIVITY_DIGEST_QUERY = gql`
  mutation TriggerActivityDigestAdd($input: TriggerActivityDigestAddInput!) {
    triggerActivityDigestAdd(input: $input) {
      id
      name
    }
  }
`;
const READ_TRIGGER_ACTIVITY_QUERY = gql`
  query triggerActivity($id: String!) {
    triggerActivity(id: $id) {
      id
      name
    }
  }
`;
const DELETE_TRIGGER_ACTIVITY_QUERY = gql`
  mutation TriggerActivityDelete($id: ID!) {
    triggerActivityDelete(id: $id)
  }
`;
const UPDATE_TRIGGER_ACTIVITY_QUERY = gql`
  mutation TriggerActivityEdit($id: ID!, $input: [EditInput!]!) {
    triggerActivityFieldPatch(id: $id, input: $input) {
      id
      name
    }
  }
`;
const LIST_TRIGGERS_ACTIVITY_QUERY = gql`
  query triggersActivity(
    $search: String
    $filters: FilterGroup
  ) {
    triggersActivity(search: $search, filters: $filters) {
      edges {
        node {
          id
          name
          trigger_type
          event_types
          description
          created
          modified
          notifiers {
            id
            name
          }
        }
      }
    }
  }
`;
const LIST_TRIGGERS_QUERY = gql`
  query triggers(
    $search: String
    $filters: FilterGroup
    $includeAuthorities: Boolean
  ) {
    triggers(search: $search, filters: $filters, includeAuthorities: $includeAuthorities) {
      edges {
        node {
          id
          name
          trigger_type
          event_types
          description
          created
          modified
          notifiers {
            id
            name
          }
        }
      }
    }
  }
`;
// end region

describe('Trigger knowledge resolver standard behavior', () => {
  let triggerInternalId;
  let digestInternalId;
  let triggerUserInternalId;
  let triggerGroupInternalId;
  let triggerOrganizationInternalId;
  // region User trigger
  it('should live trigger created', async () => {
    // Create the trigger
    const TRIGGER_TO_CREATE = {
      input: {
        name: 'live trigger',
        description: '',
        event_types: [EVENT_TYPE_CREATE],
        notifiers: [],
        instance_trigger: false,
      },
    };
    const trigger = await queryAsAdmin({ query: CREATE_TRIGGER_KNOWLEDGE_LIVE_QUERY, variables: TRIGGER_TO_CREATE });
    expect(trigger).not.toBeNull();
    expect(trigger.data.triggerKnowledgeLiveAdd).not.toBeNull();
    expect(trigger.data.triggerKnowledgeLiveAdd.name).toEqual('live trigger');
    triggerInternalId = trigger.data.triggerKnowledgeLiveAdd.id;
  });
  it('should regular digest created', async () => {
    // Create the digest
    const DIGEST_TO_CREATE = {
      input: {
        name: 'regular digest',
        description: '',
        trigger_ids: [triggerInternalId],
        period: 'hour',
        trigger_time: '',
        notifiers: [],
      },
    };
    const digest = await queryAsAdmin({ query: CREATE_TRIGGER_KNOWLEDGE_DIGEST_QUERY, variables: DIGEST_TO_CREATE });
    expect(digest).not.toBeNull();
    expect(digest.data.triggerKnowledgeDigestAdd).not.toBeNull();
    expect(digest.data.triggerKnowledgeDigestAdd.name).toEqual('regular digest');
    digestInternalId = digest.data.triggerKnowledgeDigestAdd.id;
  });
  it('should trigger loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_TRIGGER_KNOWLEDGE_QUERY, variables: { id: triggerInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.triggerKnowledge).not.toBeNull();
    expect(queryResult.data.triggerKnowledge.id).toEqual(triggerInternalId);
  });
  it('security user should create trigger for Admin user', async () => {
    // Create the trigger
    const TRIGGER_TO_CREATE_FOR_USER = {
      input: {
        name: 'trigger',
        description: '',
        event_types: [EVENT_TYPE_CREATE],
        notifiers: [],
        recipients: [ADMIN_USER.id],
        instance_trigger: false,
      },
    };
    const trigger = await securityQuery({ query: CREATE_TRIGGER_KNOWLEDGE_LIVE_QUERY, variables: TRIGGER_TO_CREATE_FOR_USER });
    expect(trigger).not.toBeNull();
    expect(trigger.data.triggerKnowledgeLiveAdd).not.toBeNull();
    expect(trigger.data.triggerKnowledgeLiveAdd.name).toEqual('trigger');
    triggerUserInternalId = trigger.data.triggerKnowledgeLiveAdd.id;
  });
  it('should list triggers', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_TRIGGERS_KNOWLEDGE_QUERY, variables: { first: 10 } });
    expect(queryResult.data.triggersKnowledge.edges.length).toEqual(3);
  });
  it('security user should list Admin triggers', async () => {
    const variables = {
      includeAuthorities: true,
      filters: {
        mode: 'and',
        filters: [{ key: 'authorized_members.id', values: [ADMIN_USER.id] }],
        filterGroups: [],
      }
    };
    const queryResult = await securityQuery({ query: LIST_TRIGGERS_KNOWLEDGE_QUERY, variables });
    expect(queryResult.data.triggersKnowledge.edges.length).toEqual(3);
  });
  it('should update trigger', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_TRIGGER_KNOWLEDGE_QUERY,
      variables: { id: triggerInternalId, input: { key: 'name', value: ['live trigger - updated'] } },
    });
    expect(queryResult.data.triggerKnowledgeFieldPatch.name).toEqual('live trigger - updated');
  });
  it('should trigger deleted', async () => {
    // Delete the trigger
    await queryAsAdmin({ query: DELETE_TRIGGER_KNOWLEDGE_QUERY, variables: { id: triggerInternalId } });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_TRIGGER_KNOWLEDGE_QUERY, variables: { id: triggerInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.triggerKnowledge).toBeNull();
  });
  it('should regular digest deleted', async () => {
    // Delete the digest
    await queryAsAdmin({ query: DELETE_TRIGGER_KNOWLEDGE_QUERY, variables: { id: digestInternalId } });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_TRIGGER_KNOWLEDGE_QUERY, variables: { id: digestInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.triggerKnowledge).toBeNull();
  });
  it('security user should Admin trigger deleted', async () => {
    // Delete the trigger
    await securityQuery({
      query: DELETE_TRIGGER_KNOWLEDGE_QUERY,
      variables: { id: triggerUserInternalId },
    });
    // Verify is no longer found
    const queryResult = await securityQuery({ query: READ_TRIGGER_KNOWLEDGE_QUERY, variables: { id: triggerUserInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.triggerKnowledge).toBeNull();
  });
  // endregion
  // region Group trigger
  it('security user should create group trigger', async () => {
    // Create the trigger
    const GROUP_TRIGGER_TO_CREATE = {
      input: {
        name: 'group trigger',
        description: '',
        event_types: [EVENT_TYPE_CREATE],
        notifiers: [],
        recipients: [AMBER_GROUP.id],
        instance_trigger: false,
      },
    };
    const trigger = await securityQuery({
      query: CREATE_TRIGGER_KNOWLEDGE_LIVE_QUERY,
      variables: GROUP_TRIGGER_TO_CREATE,
    });
    expect(trigger).not.toBeNull();
    expect(trigger.data.triggerKnowledgeLiveAdd).not.toBeNull();
    expect(trigger.data.triggerKnowledgeLiveAdd.name).toEqual('group trigger');
    triggerGroupInternalId = trigger.data.triggerKnowledgeLiveAdd.id;
  });
  it('editor user should list group triggers via knowledge triggers API', async () => {
    const queryResult = await editorQuery({ query: LIST_TRIGGERS_KNOWLEDGE_QUERY, variables: { first: 10 } });
    expect(queryResult.data.triggersKnowledge.edges.length).toEqual(1);
  });
  it('editor user should list group triggers via triggers API', async () => {
    const queryResult = await editorQuery({ query: LIST_TRIGGERS_QUERY, variables: { first: 10 } });
    expect(queryResult.data.triggers.edges.length).toEqual(1);
  });
  it('editor user should not update group trigger', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
      query: UPDATE_TRIGGER_KNOWLEDGE_QUERY,
      variables: { id: triggerGroupInternalId, input: { key: 'name', value: ['group trigger - updated'] } },
    });
  });
  it('security user should group trigger deleted', async () => {
    // Delete the trigger
    await securityQuery({ query: DELETE_TRIGGER_KNOWLEDGE_QUERY, variables: { id: triggerGroupInternalId } });
    // Verify is no longer found
    const queryResult = await securityQuery({ query: READ_TRIGGER_KNOWLEDGE_QUERY, variables: { id: triggerGroupInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.triggerKnowledge).toBeNull();
  });
  // endregion
  // region Organization trigger
  it('security user should create organization trigger', async () => {
    // Create the trigger
    const ORGANIZATION_TRIGGER_TO_CREATE = {
      input: {
        name: 'organization trigger',
        description: '',
        event_types: [EVENT_TYPE_CREATE],
        notifiers: [],
        recipients: [AMBER_GROUP.id],
        instance_trigger: false,
      },
    };
    const trigger = await securityQuery({
      query: CREATE_TRIGGER_KNOWLEDGE_LIVE_QUERY,
      variables: ORGANIZATION_TRIGGER_TO_CREATE,
    });
    expect(trigger).not.toBeNull();
    expect(trigger.data.triggerKnowledgeLiveAdd).not.toBeNull();
    expect(trigger.data.triggerKnowledgeLiveAdd.name).toEqual('organization trigger');
    triggerOrganizationInternalId = trigger.data.triggerKnowledgeLiveAdd.id;
  });
  it('editor user should list organization trigger', async () => {
    const queryResult = await editorQuery({ query: LIST_TRIGGERS_KNOWLEDGE_QUERY, variables: { first: 10 } });
    expect(queryResult.data.triggersKnowledge.edges.length).toEqual(1);
  });
  it('editor user should not update organization trigger', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
      query: UPDATE_TRIGGER_KNOWLEDGE_QUERY,
      variables: { id: triggerOrganizationInternalId, input: { key: 'name', value: ['organization trigger - updated'] } },
    });
  });
  it('security user should organization trigger deleted', async () => {
    // Delete the trigger
    await securityQuery({ query: DELETE_TRIGGER_KNOWLEDGE_QUERY, variables: { id: triggerOrganizationInternalId } });
    // Verify is no longer found
    const queryResult = await securityQuery({ query: READ_TRIGGER_KNOWLEDGE_QUERY, variables: { id: triggerOrganizationInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.triggerKnowledge).toBeNull();
  });
  // endregion
});

describe('Trigger activity resolver standard behavior', () => {
  const TRIGGER_ACTIVITY_LIVE_TO_CREATE = {
    input: {
      name: 'activity live trigger',
      description: '',
      notifiers: ['f4ee7b33-006a-4b0d-b57d-411ad288653d'],
      recipients: [USER_SECURITY.id],
    },
  };
  let triggerActivityLiveInternalId;
  let triggerActivityDigestInternalId;
  it('should activity live trigger created', async () => {
    // Create the trigger
    const trigger = await securityQuery({ query: CREATE_TRIGGER_ACTIVITY_LIVE_QUERY, variables: TRIGGER_ACTIVITY_LIVE_TO_CREATE });
    expect(trigger).not.toBeNull();
    expect(trigger.data.triggerActivityLiveAdd).not.toBeNull();
    expect(trigger.data.triggerActivityLiveAdd.name).toEqual('activity live trigger');
    triggerActivityLiveInternalId = trigger.data.triggerActivityLiveAdd.id;
  });
  it('should activity regular digest created', async () => {
    const TRIGGER_ACTIVITY_DIGEST_TO_CREATE = {
      input: {
        name: 'activity regular digest',
        trigger_ids: [triggerActivityLiveInternalId],
        period: 'hour',
        notifiers: ['f4ee7b33-006a-4b0d-b57d-411ad288653d'],
        recipients: [USER_SECURITY.id],
      },
    };
    // Create the digest
    const digest = await securityQuery({ query: CREATE_TRIGGER_ACTIVITY_DIGEST_QUERY, variables: TRIGGER_ACTIVITY_DIGEST_TO_CREATE });
    expect(digest).not.toBeNull();
    expect(digest.data.triggerActivityDigestAdd).not.toBeNull();
    expect(digest.data.triggerActivityDigestAdd.name).toEqual('activity regular digest');
    triggerActivityDigestInternalId = digest.data.triggerActivityDigestAdd.id;
  });
  it('should activity live trigger loaded by internal id', async () => {
    const queryResult = await securityQuery({ query: READ_TRIGGER_ACTIVITY_QUERY, variables: { id: triggerActivityLiveInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.triggerActivity).not.toBeNull();
    expect(queryResult.data.triggerActivity.id).toEqual(triggerActivityLiveInternalId);
    expect(queryResult.data.triggerActivity.name).toEqual('activity live trigger');
  });
  it('should activity digest trigger loaded by internal id', async () => {
    const queryResult = await securityQuery({ query: READ_TRIGGER_ACTIVITY_QUERY, variables: { id: triggerActivityDigestInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.triggerActivity).not.toBeNull();
    expect(queryResult.data.triggerActivity.id).toEqual(triggerActivityDigestInternalId);
    expect(queryResult.data.triggerActivity.name).toEqual('activity regular digest');
  });
  // make sure editor can't call activity APIs (missing capa)
  it('editor user should not create / read / list / update / delete activity live trigger', async () => {
    // create forbidden
    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
      query: CREATE_TRIGGER_ACTIVITY_LIVE_QUERY,
      variables: TRIGGER_ACTIVITY_LIVE_TO_CREATE,
    });
    const TRIGGER_ACTIVITY_DIGEST_TO_CREATE = {
      input: {
        name: 'activity regular digest',
        trigger_ids: [triggerActivityLiveInternalId],
        period: 'hour',
        notifiers: ['f4ee7b33-006a-4b0d-b57d-411ad288653d'],
        recipients: [USER_SECURITY.id],
      },
    };
    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
      query: CREATE_TRIGGER_ACTIVITY_DIGEST_QUERY,
      variables: TRIGGER_ACTIVITY_DIGEST_TO_CREATE,
    });
    // read forbidden
    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
      query: READ_TRIGGER_ACTIVITY_QUERY,
      variables: { id: triggerActivityLiveInternalId },
    });
    // update forbidden
    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
      query: UPDATE_TRIGGER_ACTIVITY_QUERY,
      variables: { id: triggerActivityLiveInternalId, input: { key: 'name', value: ['activity live trigger - updated'] } },
    });
    // delete forbidden
    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
      query: DELETE_TRIGGER_ACTIVITY_QUERY,
      variables: { id: triggerActivityLiveInternalId },
    });
    // list forbidden
    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
      query: LIST_TRIGGERS_ACTIVITY_QUERY,
      variables: { first: 10 },
    });
  });
  // list activity triggers
  it('security user should list activity triggers', async () => {
    const queryResult = await securityQuery({ query: LIST_TRIGGERS_ACTIVITY_QUERY, variables: { first: 10 } });
    expect(queryResult.data.triggersActivity.edges.length).toEqual(2);
  });
  // update activity trigger
  it('should update trigger', async () => {
    const queryResult = await securityQuery({
      query: UPDATE_TRIGGER_ACTIVITY_QUERY,
      variables: { id: triggerActivityLiveInternalId, input: { key: 'name', value: ['activity live trigger - updated'] } },
    });
    expect(queryResult.data.triggerActivityFieldPatch.name).toEqual('activity live trigger - updated');
  });
  // create knowledge trigger & list all triggers & delete knowledge trigger
  it('security user should list all triggers', async () => {
    // Create a trigger knowledge live
    const TRIGGER_TO_CREATE = {
      input: {
        name: 'live trigger for security user',
        description: '',
        event_types: [EVENT_TYPE_CREATE],
        notifiers: [],
        instance_trigger: false,
      },
    };
    const trigger = await securityQuery({ query: CREATE_TRIGGER_KNOWLEDGE_LIVE_QUERY, variables: TRIGGER_TO_CREATE });
    expect(trigger).not.toBeNull();
    expect(trigger.data.triggerKnowledgeLiveAdd).not.toBeNull();
    const triggerToDeleteId = trigger.data.triggerKnowledgeLiveAdd.id;
    // list all triggers => we should have now 3 triggers : 2 activity & 1 knowledge
    let queryResult = await securityQuery({ query: LIST_TRIGGERS_QUERY, variables: { first: 10 } });
    expect(queryResult.data.triggers.edges.length).toEqual(3);
    // delete the live trigger
    await securityQuery({ query: DELETE_TRIGGER_KNOWLEDGE_QUERY, variables: { id: triggerToDeleteId } });
    // list all triggers => we should have now only 2 triggers
    queryResult = await securityQuery({ query: LIST_TRIGGERS_QUERY, variables: { first: 10 } });
    expect(queryResult.data.triggers.edges.length).toEqual(2);
  });
  // delete activity triggers
  it('security user should delete all activity triggers', async () => {
    // Delete live & digest trigger
    await securityQuery({ query: DELETE_TRIGGER_ACTIVITY_QUERY, variables: { id: triggerActivityLiveInternalId } });
    await securityQuery({ query: DELETE_TRIGGER_ACTIVITY_QUERY, variables: { id: triggerActivityDigestInternalId } });
    // Verify there is no activity triggers
    const queryResult = await securityQuery({ query: LIST_TRIGGERS_ACTIVITY_QUERY, variables: { first: 10 } });
    expect(queryResult.data.triggersActivity.edges.length).toEqual(0);
  });
});
