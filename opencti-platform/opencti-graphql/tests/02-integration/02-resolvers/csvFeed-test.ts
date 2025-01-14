import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { editorQuery, queryAsAdmin } from '../../utils/testQuery';

describe('CSV Feed resolver standard behavior', () => {
  let internalFeedId: string;

  it('should create CSV Feed', async () => {
    const CREATE_FEED = gql(`
      mutation FeedAdd($input: FeedAddInput!) {
        feedAdd(input: $input) {
          id
          name
          feed_types
        }
      }
    `);
    const feed = await queryAsAdmin({
      query: CREATE_FEED,
      variables: {
        input: {
          name: 'List of created cities',
          separator: ';',
          rolling_time: 60,
          include_header: true,
          feed_types: ['City'],
          feed_date_attribute: 'created_at',
          feed_attributes: [{
            attribute: 'A',
            mappings: [{ type: 'City', attribute: 'name' }]
          }]
        }
      },
    });
    expect(feed).not.toBeNull();
    expect(feed.data?.feedAdd.name).toEqual('List of created cities');
    internalFeedId = feed.data?.feedAdd.id;
  });

  it('should access feed if user has capa to manage feeds', async () => {
    const QUERY_FEED = gql(`
      query QueryFeed($id: String!) {
        feed(id: $id) {
          id
          name
        }
      }
    `);
    const feed = await editorQuery({
      query: QUERY_FEED,
      variables: { id: internalFeedId }
    });
    expect(feed).not.toBeNull();
    expect(feed.data?.feed.name).toEqual('List of created cities');
  });
});
