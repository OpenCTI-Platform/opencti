import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, AMBER_GROUP, editorQuery, queryAsAdmin, securityQuery } from '../../utils/testQuery';
import { EVENT_TYPE_CREATE } from '../../../src/database/utils';

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
        outcomes: [],
        filters: '',
        instance_trigger: false,
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
  it('security user should create trigger for Admin user', async () => {
    // Create the trigger
    const TRIGGER_TO_CREATE_FOR_USER = {
      input: {
        name: 'trigger',
        description: '',
        event_types: [EVENT_TYPE_CREATE],
        outcomes: [],
        filters: '',
        recipients: [ADMIN_USER.id],
        instance_trigger: false,
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
  it('should list triggers', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.triggers.edges.length).toEqual(3);
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
  // endregion
  // region Group trigger
  it('security user should create group trigger', async () => {
    // Create the trigger
    const GROUP_TRIGGER_TO_CREATE = {
      input: {
        name: 'group trigger',
        description: '',
        event_types: [EVENT_TYPE_CREATE],
        outcomes: [],
        filters: '',
        recipients: [AMBER_GROUP.id],
        instance_trigger: false,
      },
    };
    const trigger = await securityQuery({
      query: CREATE_LIVE_QUERY,
      variables: GROUP_TRIGGER_TO_CREATE,
    });
    expect(trigger).not.toBeNull();
    expect(trigger.data.triggerLiveAdd).not.toBeNull();
    expect(trigger.data.triggerLiveAdd.name).toEqual('group trigger');
    triggerGroupInternalId = trigger.data.triggerLiveAdd.id;
  });
  it('editor user should list group trigger', async () => {
    const queryResult = await editorQuery({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.triggers.edges.length).toEqual(1);
  });
  it('editor user should not update group trigger', async () => {
    const queryResult = await editorQuery({
      query: UPDATE_QUERY,
      variables: { id: triggerGroupInternalId, input: { key: 'name', value: ['group trigger - updated'] } },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.errors.length).toEqual(1);
    expect(queryResult.errors.at(0).name).toEqual('ForbiddenAccess');
  });
  it('security user should group trigger deleted', async () => {
    // Delete the trigger
    await securityQuery({
      query: DELETE_QUERY,
      variables: { id: triggerGroupInternalId },
    });
    // Verify is no longer found
    const queryResult = await securityQuery({ query: READ_QUERY, variables: { id: triggerGroupInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.trigger).toBeNull();
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
        outcomes: [],
        filters: '',
        recipients: [AMBER_GROUP.id],
        instance_trigger: false,
      },
    };
    const trigger = await securityQuery({
      query: CREATE_LIVE_QUERY,
      variables: ORGANIZATION_TRIGGER_TO_CREATE,
    });
    expect(trigger).not.toBeNull();
    expect(trigger.data.triggerLiveAdd).not.toBeNull();
    expect(trigger.data.triggerLiveAdd.name).toEqual('organization trigger');
    triggerOrganizationInternalId = trigger.data.triggerLiveAdd.id;
  });
  it('editor user should list organization trigger', async () => {
    const queryResult = await editorQuery({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.triggers.edges.length).toEqual(1);
  });
  it('editor user should not update organization trigger', async () => {
    const queryResult = await editorQuery({
      query: UPDATE_QUERY,
      variables: { id: triggerOrganizationInternalId, input: { key: 'name', value: ['organization trigger - updated'] } },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.errors.length).toEqual(1);
    expect(queryResult.errors.at(0).name).toEqual('ForbiddenAccess');
  });
  it('security user should organization trigger deleted', async () => {
    // Delete the trigger
    await securityQuery({
      query: DELETE_QUERY,
      variables: { id: triggerOrganizationInternalId },
    });
    // Verify is no longer found
    const queryResult = await securityQuery({ query: READ_QUERY, variables: { id: triggerOrganizationInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.trigger).toBeNull();
  });
  // endregion
});
