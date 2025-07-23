import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { editorQuery, queryAsAdmin, USER_PARTICIPATE } from '../../utils/testQuery';
import { queryAsAdminWithSuccess, queryAsUser } from '../../utils/testQueryHelper';
import { logApp } from '../../../src/config/conf';

describe('CSV Feed resolver standard behavior', () => {
  let internalFeedId: string;
  let publicFeedId: string;

  it('should create restricted CSV Feed', async () => {
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
          name: 'List of created cities - internal csv feed',
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
    expect(feed.data?.feedAdd.name).toEqual('List of created cities - internal csv feed');
    internalFeedId = feed.data?.feedAdd.id;
  });

  it('should create public CSV Feed', async () => {
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
          name: 'List of created countries - public csv feed',
          separator: '|',
          rolling_time: 60,
          include_header: true,
          feed_types: ['Country'],
          feed_date_attribute: 'created_at',
          feed_attributes: [{
            attribute: 'A',
            mappings: [{ type: 'Country', attribute: 'name' }]
          }],
          feed_public: true
        }
      },
    });
    expect(feed).not.toBeNull();
    expect(feed.data?.feedAdd.name).toEqual('List of created countries - public csv feed');
    publicFeedId = feed.data?.feedAdd.id;
  });

  it('should update public CSV Feed', async () => {
    const UPDATE_FEED = gql(`
      mutation FeedEdition($id: ID!, $input: FeedAddInput!) {
          feedEdit(id: $id, input: $input) {
          id
          name
          description
          feed_public
          authorized_members {
            id
            member_id
            name
          }
        }
      }
    `);
    const feed = await queryAsAdminWithSuccess({
      query: UPDATE_FEED,
      variables: {
        id: publicFeedId,
        input: {
          name: 'List of created countries - public csv feed',
          description: 'Description updated',
          separator: '|',
          rolling_time: 60,
          include_header: true,
          feed_types: ['Country'],
          feed_date_attribute: 'created_at',
          feed_attributes: [{
            attribute: 'A',
            mappings: [{ type: 'Country', attribute: 'name' }]
          }],
          feed_public: true,
          authorized_members: [],
        }
      },
    });
    expect(feed).not.toBeNull();
    expect(feed.data?.feedEdit.description).toEqual('Description updated');
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
    expect(feed.data?.feed.name).toEqual('List of created cities - internal csv feed');
  });

  it('List all CSV Feed collection with Admin', async () => {
    const allFeedsResponse = await queryAsAdminWithSuccess({
      query: gql`
        query feeds {
          feeds(search: "") {
            edges {
              node {
                id
                name
                feed_public
                authorized_members {
                  id
                  name
                }
              }
            }
          }
        },
      `,
      variables: {}
    });

    logApp.info('allFeedsResponse:', allFeedsResponse);
    // Public feed should be found
    expect(allFeedsResponse?.data?.feeds?.edges
      .filter((feed: any) => feed.node.name === 'List of created countries - public csv feed').length).toBe(1);

    // Internal feed should be found too
    expect(allFeedsResponse?.data?.feeds?.edges
      .filter((feed: any) => feed.node.name === 'List of created cities - internal csv feed').length).toBe(1);
  });

  it('List all CSV Feed with a user that has not TAXIIAPI capacity', async () => {
    const allFeedsResponse = await queryAsUser(USER_PARTICIPATE.client, {
      query: gql`
        query feeds {
          feeds(search: "") {
            edges {
              node {
                id
                name
                feed_public
                authorized_members {
                  id
                  name
                }
              }
            }
          }
        },
      `,
      variables: {}
    });

    logApp.info('allFeedsResponse:', allFeedsResponse);

    // Public feed should be found
    expect(allFeedsResponse?.data?.feeds?.edges
      .filter((feed: any) => feed.node.name === 'List of created countries - public csv feed').length).toBe(1);

    // Internal feed should not be found
    expect(allFeedsResponse?.data?.feeds?.edges
      .filter((feed: any) => feed.node.name === 'List of created cities - internal csv feed').length).toBe(0);
  });

  it('Delete public feed collection', async () => {
    const deletePublicFeedResponse = await queryAsAdminWithSuccess({
      query: gql`
        mutation feedDelete($id: ID!) {
          feedDelete(id: $id)
        },
      `,
      variables: { id: publicFeedId }
    });
    logApp.info('deletePublicFeedResponse:', deletePublicFeedResponse);
  });

  it('Delete internal feed collection', async () => {
    const deleteFeedResponse = await queryAsAdminWithSuccess({
      query: gql`
        mutation feedDelete($id: ID!) {
          feedDelete(id: $id)
        },
      `,
      variables: { id: internalFeedId }
    });
    logApp.info('deleteFeedResponse:', deleteFeedResponse);
  });
});
