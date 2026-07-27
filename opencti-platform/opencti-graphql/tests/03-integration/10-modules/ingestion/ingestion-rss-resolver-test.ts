import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdminWithSuccess } from '../../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { queryAsAdmin } from '../../../utils/testQueryHelper';
import { findById as findUserById } from '../../../../src/domain/user';

const DELETE_USER_QUERY = gql`
    mutation userDelete($id: ID!) {
        userEdit(id: $id) {
            delete
        }
    }
`;

const READ_USER_QUERY = gql`
    query user($id: String!) {
        user(id: $id) {
            id
            name
            description
            user_confidence_level {
                max_confidence
            }
        }
    }
`;

describe('RSS ingestion resolver standard behavior', () => {
  let createdRssIngesterId: string = '';

  it('should create an RSS ingester', async () => {
    const INGESTER_TO_CREATE = {
      input: {
        name: 'RSS ingester for integration test',
        uri: 'http://rss-feed.invalid/feed.xml',
        user_id: ADMIN_USER.id,
        scheduling_period: 'PT1H',
        ingestion_running: false,
      },
    };
    const ingesterQueryResult = await queryAsAdminWithSuccess({
      query: gql`
        mutation createRssIngester($input: IngestionRssAddInput!) {
          ingestionRssAdd(input: $input) {
            id
            entity_type
            name
            uri
            ingestion_running
          }
        }
      `,
      variables: INGESTER_TO_CREATE,
    });
    expect(ingesterQueryResult.data?.ingestionRssAdd.id).toBeDefined();
    expect(ingesterQueryResult.data?.ingestionRssAdd.name).toBe('RSS ingester for integration test');
    expect(ingesterQueryResult.data?.ingestionRssAdd.uri).toBe('http://rss-feed.invalid/feed.xml');
    expect(ingesterQueryResult.data?.ingestionRssAdd.ingestion_running).toBe(false);
    createdRssIngesterId = ingesterQueryResult.data?.ingestionRssAdd.id;
  });

  it('should read the created RSS ingester', async () => {
    const queryResult = await queryAsAdminWithSuccess({
      query: gql`
        query readRssIngester($id: String!) {
          ingestionRss(id: $id) {
            id
            name
            uri
            ingestion_running
            current_state_date
          }
        }
      `,
      variables: { id: createdRssIngesterId },
    });
    expect(queryResult.data?.ingestionRss.id).toBe(createdRssIngesterId);
    expect(queryResult.data?.ingestionRss.name).toBe('RSS ingester for integration test');
    expect(queryResult.data?.ingestionRss.uri).toBe('http://rss-feed.invalid/feed.xml');
  });

  it('should list RSS ingesters', async () => {
    const queryResult = await queryAsAdminWithSuccess({
      query: gql`
        query listRssIngesters {
          ingestionRsss {
            edges {
              node {
                id
                name
                uri
              }
            }
          }
        }
      `,
    });
    const edges = queryResult.data?.ingestionRsss.edges;
    expect(edges).toBeDefined();
    expect(edges.length).toBeGreaterThanOrEqual(1);
    const found = edges.find((e: any) => e.node.id === createdRssIngesterId);
    expect(found).toBeDefined();
    expect(found.node.name).toBe('RSS ingester for integration test');
  });

  it('should generate correct export configuration', async () => {
    const queryResult = await queryAsAdminWithSuccess({
      query: gql`
        query queryRssFeed($id: String!) {
          ingestionRss(id: $id) {
            name
            toConfigurationExport
          }
        }
      `,
      variables: { id: createdRssIngesterId },
    });
    const rssFeedIngestion = JSON.parse(queryResult.data?.ingestionRss.toConfigurationExport);
    expect(rssFeedIngestion.configuration).toMatchObject({
      name: 'RSS ingester for integration test',
      uri: 'http://rss-feed.invalid/feed.xml',
    });
  });

  it('should create an RSS feed with automatic user', async () => {
    const INGESTER_TO_CREATE = {
      input: {
        name: 'RSS ingester auto user test',
        uri: 'http://rss-feed.invalid/auto-user.xml',
        automatic_user: true,
        user_id: '[F] RSS ingester auto user test',
        scheduling_period: 'PT1H',
      },
    };
    const ingesterQueryResult = await queryAsAdminWithSuccess({
      query: gql`
        mutation createRssIngester($input: IngestionRssAddInput!) {
          ingestionRssAdd(input: $input) {
            id
            entity_type
            ingestion_running
            user {
              id
              name
            }
          }
        }
      `,
      variables: INGESTER_TO_CREATE,
    });
    expect(ingesterQueryResult.data?.ingestionRssAdd.id).toBeDefined();
    const createdIngester = ingesterQueryResult.data?.ingestionRssAdd;
    const userId = createdIngester.user?.id;
    expect(userId).toBeDefined();

    const createdUser = await findUserById(testContext, ADMIN_USER, userId);
    expect(createdUser.name).toBe('[F] RSS ingester auto user test');

    // Clean up: delete the ingester and user
    await queryAsAdmin({
      query: gql`
        mutation deleteRssIngester($id: ID!) {
          ingestionRssDelete(id: $id)
        }
      `,
      variables: { id: createdIngester.id },
    });
    await queryAsAdmin({
      query: DELETE_USER_QUERY,
      variables: { id: userId },
    });
    // Verify user no longer found
    const queryResult = await queryAsAdmin({ query: READ_USER_QUERY, variables: { id: userId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.user).toBeNull();
  });

  it('should update an RSS ingester', async () => {
    const ingesterQueryResult = await queryAsAdminWithSuccess({
      query: gql`
        mutation ingestionRssFieldPatch($id: ID!, $input: [EditInput!]!) {
          ingestionRssFieldPatch(id: $id, input: $input) {
            id
            name
            uri
          }
        }
      `,
      variables: {
        id: createdRssIngesterId,
        input: [{ key: 'name', value: ['RSS ingester updated'] }],
      },
    });
    expect(ingesterQueryResult.data?.ingestionRssFieldPatch.id).toBe(createdRssIngesterId);
    expect(ingesterQueryResult.data?.ingestionRssFieldPatch.name).toBe('RSS ingester updated');
  });

  it('should update the URI of an RSS ingester', async () => {
    const ingesterQueryResult = await queryAsAdminWithSuccess({
      query: gql`
        mutation ingestionRssFieldPatch($id: ID!, $input: [EditInput!]!) {
          ingestionRssFieldPatch(id: $id, input: $input) {
            id
            uri
          }
        }
      `,
      variables: {
        id: createdRssIngesterId,
        input: [{ key: 'uri', value: ['http://rss-feed.invalid/updated-feed.xml'] }],
      },
    });
    expect(ingesterQueryResult.data?.ingestionRssFieldPatch.id).toBe(createdRssIngesterId);
    expect(ingesterQueryResult.data?.ingestionRssFieldPatch.uri).toBe('http://rss-feed.invalid/updated-feed.xml');
  });

  it('should add auto user and update RSS ingester with it', async () => {
    const RSS_AUTO_USER_UPDATE = {
      id: createdRssIngesterId,
      input: {
        user_name: 'RssAutoUser',
        confidence_level: 75,
      },
    };
    const updateResult = await queryAsAdminWithSuccess({
      query: gql`
        mutation updateRssWithAutoUser($id: ID!, $input: IngestionRssAddAutoUserInput!) {
          ingestionRssAddAutoUser(id: $id, input: $input) {
            id
            user {
              id
              name
            }
          }
        }
      `,
      variables: RSS_AUTO_USER_UPDATE,
    });
    expect(updateResult?.data?.ingestionRssAddAutoUser?.user?.name).toBe('RssAutoUser');
    // Delete just created user
    await queryAsAdmin({
      query: DELETE_USER_QUERY,
      variables: { id: updateResult?.data?.ingestionRssAddAutoUser?.user?.id },
    });
    // Verify no longer found
    const queryResult = await queryAsAdmin({
      query: READ_USER_QUERY,
      variables: { id: updateResult?.data?.ingestionRssAddAutoUser?.user?.id },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.user).toBeNull();
  });

  it('should delete the RSS ingester', async () => {
    const ingesterQueryResult = await queryAsAdminWithSuccess({
      query: gql`
        mutation deleteRssIngester($id: ID!) {
          ingestionRssDelete(id: $id)
        }
      `,
      variables: { id: createdRssIngesterId },
    });
    expect(ingesterQueryResult.data?.ingestionRssDelete).toEqual(createdRssIngesterId);
  });

  it('should not find the deleted RSS ingester', async () => {
    const queryResult = await queryAsAdmin({
      query: gql`
        query readRssIngester($id: String!) {
          ingestionRss(id: $id) {
            id
          }
        }
      `,
      variables: { id: createdRssIngesterId },
    });
    expect(queryResult.data?.ingestionRss).toBeNull();
  });
});
