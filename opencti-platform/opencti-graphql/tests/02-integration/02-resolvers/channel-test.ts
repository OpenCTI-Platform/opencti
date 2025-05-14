import gql from 'graphql-tag';
import { describe, expect, it } from 'vitest';
import type { ChannelAddInput } from '../../../src/generated/graphql';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query channels(
    $filters: FilterGroup
    $search: String
    $first: Int
    $after: ID
    $orderBy: ChannelsOrdering
    $orderMode: OrderingMode
  ) {
    channels(
      filters: $filters
      search: $search
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
    ) {
      edges {
        node {
          id
          name
          description
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query channel($id: String!) {
    channel(id: $id) {
      id
      standard_id
      entity_type
      name
    }
  }
`;

const CHANNEL: ChannelAddInput = {
  name: 'channel.com',
  description: 'channel description',
  channel_types: ['Twitter']
};

describe('Channel resolver standard behavior', () => {
  let channelId: string;
  // const stixCoreRelationshipStixId = 'relationship--3d8aa13a-6cad-493d-133a-ae4ff5a203ca';
  it('should create threat actor individual', async () => {
    const CREATE_QUERY = gql`
      mutation channelAdd($input: ChannelAddInput!) {
        channelAdd(input: $input) {
          id
          name
          description
          channel_types
        }
      }
    `;
    const channel = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: { input: CHANNEL }
    });

    expect(channel?.data).not.toBeNull();
    expect(channel.data?.channelAdd).not.toBeNull();
    expect(channel.data?.channelAdd.name).toEqual('channel.com');

    channelId = channel.data?.channelAdd.id;
  });

  it('should channel loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: channelId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.channel).not.toBeNull();
    expect(queryResult.data?.channel.id).toEqual(channelId);
  });

  it('should list channels', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data?.channels.edges.length).toBeGreaterThan(0);
  });

  /*
  it('should add relation to channel', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation ChannelRelationAdd($input: StixCoreRelationshipAddInput!) {
        stixCoreRelationshipAdd(input: $input) {
          id
        }
      }
    `;
    const RELATIONSHIP_TO_CREATE = {
      input: {
        stix_id: stixCoreRelationshipStixId,
        fromId: channelId,
        toId: ''
      }
    }
    const queryResult = await queryAsAdmin({
      query: RELATION_ADD_QUERY,
      variables: {
        id: channelId,
        input: {
          toId: taskTemplateInternalId,
          relationship_type: 'template-task',
        },
      },
    });
    expect(queryResult.data?.caseTemplateRelationAdd).not.toBeNull();
    const readQueryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: caseTemplateInternalId } });
    expect(readQueryResult).not.toBeNull();
    expect(readQueryResult.data?.caseTemplate).not.toBeNull();
    const tasks = readQueryResult.data?.caseTemplate.tasks.edges;
    expect(tasks.length).toBeGreaterThan(0);
  });
  */
});
