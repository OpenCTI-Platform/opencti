import { afterAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQueryHelper';

const CREATE_QUERY = gql`
  mutation EventAdd($input: EventAddInput!) {
    eventAdd(input: $input) {
      id
      name
      x_opencti_score
    }
  }
`;

const READ_QUERY = gql`
  query Event($id: String!) {
    event(id: $id) {
      id
      name
      x_opencti_score
    }
  }
`;

const UPDATE_SCORE_QUERY = gql`
  mutation EventEdit($id: ID!, $input: [EditInput]!) {
    eventFieldPatch(id: $id, input: $input) {
      id
      x_opencti_score
    }
  }
`;

const DELETE_QUERY = gql`
  mutation EventDelete($id: ID!) {
    eventDelete(id: $id)
  }
`;

describe('Event resolver score behavior', () => {
  let eventInternalId: string | undefined;
  const eventStixId = 'event--0de58b87-f3be-4f9b-a508-388a3fc92977';

  it('should reject event creation with score below 0', async () => {
    const queryResult = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: {
        input: {
          name: 'Event invalid score -1',
          x_opencti_score: -1,
        },
      },
    });

    expect(queryResult.errors?.length).toBe(1);
    expect(queryResult.data?.eventAdd).toBeNull();
  });

  it('should reject event creation with score above 100', async () => {
    const queryResult = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: {
        input: {
          name: 'Event invalid score 101',
          x_opencti_score: 101,
        },
      },
    });

    expect(queryResult.errors?.length).toBe(1);
    expect(queryResult.data?.eventAdd).toBeNull();
  });

  afterAll(async () => {
    if (!eventInternalId) {
      return;
    }
    await queryAsAdmin({ query: DELETE_QUERY, variables: { id: eventInternalId } });
  });

  it('should create event with score', async () => {
    const eventToCreate = {
      input: {
        name: 'Event score test',
        stix_id: eventStixId,
        description: 'Event score test description',
        x_opencti_score: 42,
      },
    };

    const event = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: eventToCreate,
    });

    expect(event).not.toBeNull();
    expect(event.data?.eventAdd).not.toBeNull();
    expect(event.data?.eventAdd.name).toEqual('Event score test');
    expect(event.data?.eventAdd.x_opencti_score).toEqual(42);
    eventInternalId = event.data?.eventAdd.id;
  });

  it('should read event score value', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: eventInternalId } });

    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.event).not.toBeNull();
    expect(queryResult.data?.event.x_opencti_score).toEqual(42);
  });

  it('should update event score with field patch', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_SCORE_QUERY,
      variables: { id: eventInternalId, input: { key: 'x_opencti_score', value: 73 } },
    });

    expect(queryResult.data?.eventFieldPatch.x_opencti_score).toEqual(73);

    const readResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: eventInternalId } });
    expect(readResult.data?.event.x_opencti_score).toEqual(73);
  });
});
