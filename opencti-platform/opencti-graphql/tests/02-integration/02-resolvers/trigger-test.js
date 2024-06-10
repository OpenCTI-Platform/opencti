import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, AMBER_GROUP, editorQuery, queryAsAdmin, securityQuery, USER_EDITOR } from '../../utils/testQuery';
import { EVENT_TYPE_CREATE } from '../../../src/database/utils';
import { queryAsUserIsExpectedForbidden } from '../../utils/testQueryHelper';

const LIST_QUERY = gql`
    query triggers(
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

const READ_QUERY = gql`
    query trigger($id: String!) {
        triggerKnowledge(id: $id) {
            id
            name
        }
    }
`;

const CREATE_LIVE_QUERY = gql`
    mutation TriggerKnowledgeLiveAdd($input: TriggerLiveAddInput!) {
        triggerKnowledgeLiveAdd(input: $input) {
            id
            name
        }
    }
`;

const CREATE_DIGEST_QUERY = gql`
    mutation TriggerKnowledgeDigestAdd($input: TriggerDigestAddInput!) {
        triggerKnowledgeDigestAdd(input: $input) {
            id
            name
        }
    }
`;

const UPDATE_QUERY = gql`
    mutation TriggerKnowledgeEdit($id: ID!, $input: [EditInput!]!) {
        triggerKnowledgeFieldPatch(id: $id, input: $input) {
            id
            name
        }
    }
`;

const DELETE_QUERY = gql`
    mutation triggerKnowledgeDelete($id: ID!) {
        triggerKnowledgeDelete(id: $id)
    }
`;

describe('Trigger resolver standard behavior', () => {
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
    const trigger = await queryAsAdmin({ query: CREATE_LIVE_QUERY, variables: TRIGGER_TO_CREATE });
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
    const digest = await queryAsAdmin({ query: CREATE_DIGEST_QUERY, variables: DIGEST_TO_CREATE });
    expect(digest).not.toBeNull();
    expect(digest.data.triggerKnowledgeDigestAdd).not.toBeNull();
    expect(digest.data.triggerKnowledgeDigestAdd.name).toEqual('regular digest');
    digestInternalId = digest.data.triggerKnowledgeDigestAdd.id;
  });
  it('should trigger loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: triggerInternalId } });
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
    const trigger = await securityQuery({ query: CREATE_LIVE_QUERY, variables: TRIGGER_TO_CREATE_FOR_USER });
    expect(trigger).not.toBeNull();
    expect(trigger.data.triggerKnowledgeLiveAdd).not.toBeNull();
    expect(trigger.data.triggerKnowledgeLiveAdd.name).toEqual('trigger');
    triggerUserInternalId = trigger.data.triggerKnowledgeLiveAdd.id;
  });
  it('should list triggers', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
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
    const queryResult = await securityQuery({ query: LIST_QUERY, variables });
    expect(queryResult.data.triggersKnowledge.edges.length).toEqual(3);
  });
  it('should update trigger', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: triggerInternalId, input: { key: 'name', value: ['live trigger - updated'] } },
    });
    expect(queryResult.data.triggerKnowledgeFieldPatch.name).toEqual('live trigger - updated');
  });
  it('should trigger deleted', async () => {
    // Delete the trigger
    await queryAsAdmin({ query: DELETE_QUERY, variables: { id: triggerInternalId } });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: triggerInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.triggerKnowledge).toBeNull();
  });
  it('should regular digest deleted', async () => {
    // Delete the digest
    await queryAsAdmin({ query: DELETE_QUERY, variables: { id: digestInternalId } });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: digestInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.triggerKnowledge).toBeNull();
  });
  it('security user should Admin trigger deleted', async () => {
    // Delete the trigger
    await securityQuery({
      query: DELETE_QUERY,
      variables: { id: triggerUserInternalId },
    });
    // Verify is no longer found
    const queryResult = await securityQuery({ query: READ_QUERY, variables: { id: triggerUserInternalId } });
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
      query: CREATE_LIVE_QUERY,
      variables: GROUP_TRIGGER_TO_CREATE,
    });
    expect(trigger).not.toBeNull();
    expect(trigger.data.triggerKnowledgeLiveAdd).not.toBeNull();
    expect(trigger.data.triggerKnowledgeLiveAdd.name).toEqual('group trigger');
    triggerGroupInternalId = trigger.data.triggerKnowledgeLiveAdd.id;
  });
  it('editor user should list group trigger', async () => {
    const queryResult = await editorQuery({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.triggersKnowledge.edges.length).toEqual(1);
  });
  it('editor user should not update group trigger', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
      query: UPDATE_QUERY,
      variables: { id: triggerGroupInternalId, input: { key: 'name', value: ['group trigger - updated'] } },
    });
  });
  it('security user should group trigger deleted', async () => {
    // Delete the trigger
    await securityQuery({ query: DELETE_QUERY, variables: { id: triggerGroupInternalId } });
    // Verify is no longer found
    const queryResult = await securityQuery({ query: READ_QUERY, variables: { id: triggerGroupInternalId } });
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
      query: CREATE_LIVE_QUERY,
      variables: ORGANIZATION_TRIGGER_TO_CREATE,
    });
    expect(trigger).not.toBeNull();
    expect(trigger.data.triggerKnowledgeLiveAdd).not.toBeNull();
    expect(trigger.data.triggerKnowledgeLiveAdd.name).toEqual('organization trigger');
    triggerOrganizationInternalId = trigger.data.triggerKnowledgeLiveAdd.id;
  });
  it('editor user should list organization trigger', async () => {
    const queryResult = await editorQuery({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.triggersKnowledge.edges.length).toEqual(1);
  });
  it('editor user should not update organization trigger', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
      query: UPDATE_QUERY,
      variables: { id: triggerOrganizationInternalId, input: { key: 'name', value: ['organization trigger - updated'] } },
    });
  });
  it('security user should organization trigger deleted', async () => {
    // Delete the trigger
    await securityQuery({ query: DELETE_QUERY, variables: { id: triggerOrganizationInternalId } });
    // Verify is no longer found
    const queryResult = await securityQuery({ query: READ_QUERY, variables: { id: triggerOrganizationInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.triggerKnowledge).toBeNull();
  });
  // endregion
});
