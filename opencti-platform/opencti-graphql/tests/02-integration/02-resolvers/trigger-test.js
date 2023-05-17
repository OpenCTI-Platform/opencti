import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin, securityQuery } from '../../utils/testQuery';

const LIST_QUERY = gql`
    query triggers(
        $search: String
        $filters: [TriggersFiltering!]
        $adminBypassUserAccess: Boolean
    ) {
        triggers(search: $search, filters: $filters, adminBypassUserAccess: $adminBypassUserAccess) {
            edges {
                node {
                    id
                    name
                    trigger_type
                    event_types
                    description
                    created
                    modified
                    outcomes
                    authorizedMembers {
                        name
                        id
                        access_right
                    }
                }
            }
        }
    }
`;

const READ_QUERY = gql`
    query trigger($id: String!) {
        trigger(id: $id) {
            id
            name
        }
    }
`;

const CREATE_LIVE_QUERY = gql`
    mutation TriggerLiveAdd($input: TriggerLiveAddInput!) {
        triggerLiveAdd(input: $input) {
            id
            name
        }
    }
`;

const CREATE_DIGEST_QUERY = gql`
    mutation TriggerDigestAdd($input: TriggerDigestAddInput!) {
        triggerDigestAdd(input: $input) {
            id
            name
        }
    }
`;

const UPDATE_QUERY = gql`
    mutation TriggerEdit($id: ID!, $input: [EditInput!]!) {
        triggerFieldPatch(id: $id, input: $input) {
            id
            name
        }
    }
`;

const DELETE_QUERY = gql`
    mutation triggerDelete($id: ID!) {
        triggerDelete(id: $id)
    }
`;

describe('Trigger resolver standard behavior', () => {
  let triggerInternalId;
  let digestInternalId;
  let triggerUserInternalId;
  it('should live trigger created', async () => {
    // Create the trigger
    const TRIGGER_TO_CREATE = {
      input: {
        name: 'live trigger',
        description: '',
        event_types: 'create',
        outcomes: [],
        filters: '',
      },
    };
    const trigger = await queryAsAdmin({
      query: CREATE_LIVE_QUERY,
      variables: TRIGGER_TO_CREATE,
    });
    expect(trigger).not.toBeNull();
    expect(trigger.data.triggerLiveAdd).not.toBeNull();
    expect(trigger.data.triggerLiveAdd.name).toEqual('live trigger');
    triggerInternalId = trigger.data.triggerLiveAdd.id;
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
        outcomes: [],
      },
    };
    const digest = await queryAsAdmin({
      query: CREATE_DIGEST_QUERY,
      variables: DIGEST_TO_CREATE,
    });
    expect(digest).not.toBeNull();
    expect(digest.data.triggerDigestAdd).not.toBeNull();
    expect(digest.data.triggerDigestAdd.name).toEqual('regular digest');
    digestInternalId = digest.data.triggerDigestAdd.id;
  });
  it('should trigger loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: triggerInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.trigger).not.toBeNull();
    expect(queryResult.data.trigger.id).toEqual(triggerInternalId);
  });
  it('should list triggers', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.triggers.edges.length).toEqual(2);
  });
  it('user with SETTINGS_SETACCESSES capability should create trigger for Admin user', async () => {
    // Create the trigger
    const TRIGGER_TO_CREATE_FOR_USER = {
      input: {
        name: 'trigger',
        description: '',
        event_types: 'create',
        outcomes: [],
        filters: '',
        recipients: [ADMIN_USER.id],
      },
    };
    const trigger = await securityQuery({
      query: CREATE_LIVE_QUERY,
      variables: TRIGGER_TO_CREATE_FOR_USER,
    });
    expect(trigger).not.toBeNull();
    expect(trigger.data.triggerLiveAdd).not.toBeNull();
    expect(trigger.data.triggerLiveAdd.name).toEqual('trigger');
    triggerUserInternalId = trigger.data.triggerLiveAdd.id;
  });
  it('security user should list Admin triggers', async () => {
    const queryResult = await securityQuery({ query: LIST_QUERY, variables: { filters: [{ key: 'user_ids', values: [ADMIN_USER.id] }] } });
    expect(queryResult.data.triggers.edges.length).toEqual(3);
  });
  it('should update trigger', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: triggerInternalId, input: { key: 'name', value: ['live trigger - updated'] } },
    });
    expect(queryResult.data.triggerFieldPatch.name).toEqual('live trigger - updated');
  });
  it('should trigger deleted', async () => {
    // Delete the trigger
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: triggerInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: triggerInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.trigger).toBeNull();
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
    expect(queryResult.data.trigger).toBeNull();
  });
  it('should regular digest deleted', async () => {
    // Delete the digest
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: digestInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: digestInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.trigger).toBeNull();
  });
});
