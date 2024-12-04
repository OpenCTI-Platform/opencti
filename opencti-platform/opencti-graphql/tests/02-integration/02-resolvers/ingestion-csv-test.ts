import { beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin, testContext, USER_PARTICIPATE } from '../../utils/testQuery';
import { queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden } from '../../utils/testQueryHelper';
import { patchCsvIngestion } from '../../../src/modules/ingestion/ingestion-csv-domain';
import { utcDate } from '../../../src/utils/format';
import { SYSTEM_USER } from '../../../src/utils/access';

describe('CSV ingestion resolver standard behavior', () => {
  let singleColumnCsvMapperId = '';
  let singleColumnCsvFeedIngesterId = '';

  beforeAll(async () => {
    const SINGLE_COLUMN_CSV_MAPPER = {
      input: {
        has_header: false,
        name: 'Single column CSV mapper',
        separator: ',',
        representations: '[{"id":"75c3c21c-0a92-497f-962d-4e6e1a488481","type":"entity","target":{"entity_type":"IPv4-Addr"},"attributes":[{"key":"value","column":{"column_name":"A"},"based_on":null}]}]',
        skipLineChar: ''
      }
    };

    const createSingleColumnCsvMapperQueryResult = await queryAsAdmin({
      query: gql`
      mutation createSingleColumnCsvMapper($input: CsvMapperAddInput!) {
        csvMapperAdd(input: $input) {
          id
        }
      },
      `,
      variables: SINGLE_COLUMN_CSV_MAPPER
    });

    singleColumnCsvMapperId = createSingleColumnCsvMapperQueryResult?.data?.csvMapperAdd?.id;
  });

  it('should create a CSV feeds ingester', async () => {
    const CSV_FEED_INGESTER_TO_CREATE = {
      input: {
        authentication_type: 'none',
        name: 'Single column',
        uri: 'https://lists.blocklist.de/lists/all.txt',
        csv_mapper_id: singleColumnCsvMapperId,
        user_id: ADMIN_USER.id
      }
    };
    const createSingleColumnCsvFeedsIngesterQueryResult = await queryAsAdmin({
      query: gql`
      mutation createSingleColumnCsvFeedsIngester($input: IngestionCsvAddInput!) {
        ingestionCsvAdd(input: $input) {
        id
        entity_type
        ingestion_running
          }
      },
      `,
      variables: CSV_FEED_INGESTER_TO_CREATE
    });
    singleColumnCsvFeedIngesterId = createSingleColumnCsvFeedsIngesterQueryResult?.data?.ingestionCsvAdd?.id;
    expect(singleColumnCsvFeedIngesterId).toBeDefined();
    expect(createSingleColumnCsvFeedsIngesterQueryResult?.data?.ingestionCsvAdd?.entity_type).toBe('IngestionCsv');
    expect(createSingleColumnCsvFeedsIngesterQueryResult?.data?.ingestionCsvAdd?.ingestion_running).toBeFalsy();
  });

  it('should create a CSV feeds ingester with authentication', async () => {
    const CSV_FEED_INGESTER_TO_CREATE = {
      input: {
        authentication_type: 'none',
        name: 'Single column',
        uri: 'https://lists.blocklist.de/lists/all.txt',
        csv_mapper_id: singleColumnCsvMapperId,
        user_id: ADMIN_USER.id
      }
    };
    const createSingleColumnCsvFeedsIngesterQueryResult = await queryAsAdmin({
      query: gql`
          mutation createSingleColumnCsvFeedsIngester($input: IngestionCsvAddInput!) {
              ingestionCsvAdd(input: $input) {
                  id
                  entity_type
                  ingestion_running
              }
          },
      `,
      variables: CSV_FEED_INGESTER_TO_CREATE
    });
    singleColumnCsvFeedIngesterId = createSingleColumnCsvFeedsIngesterQueryResult?.data?.ingestionCsvAdd?.id;
    expect(singleColumnCsvFeedIngesterId).toBeDefined();
    expect(createSingleColumnCsvFeedsIngesterQueryResult?.data?.ingestionCsvAdd?.entity_type).toBe('IngestionCsv');
    expect(createSingleColumnCsvFeedsIngesterQueryResult?.data?.ingestionCsvAdd?.ingestion_running).toBeFalsy();
  });

  it('should start the CSV feeds ingester', async () => {
    const CSV_FEED_INGESTER_TO_START = {
      id: singleColumnCsvFeedIngesterId,
      input: {
        key: 'ingestion_running',
        value: [true],
      }
    };
    const startSingleColumnCsvFeedsIngesterQueryResult = await queryAsAdmin({
      query: gql`
      mutation startSingleColumnCsvFeedsIngester($id: ID!, $input: [EditInput!]!) {
        ingestionCsvFieldPatch(id: $id, input: $input){
          ingestion_running
        }
      }
      `,
      variables: CSV_FEED_INGESTER_TO_START
    });
    expect(startSingleColumnCsvFeedsIngesterQueryResult?.data?.ingestionCsvFieldPatch?.ingestion_running).toBeTruthy();
  });

  it('should stop the CSV feeds ingester', async () => {
    const CSV_FEED_INGESTER_TO_STOP = {
      id: singleColumnCsvFeedIngesterId,
      input: {
        key: 'ingestion_running',
        value: [false],
      }
    };
    const stopSingleColumnCsvFeedsIngesterQueryResult = await queryAsAdmin({
      query: gql`
      mutation stopSingleColumnCsvFeedsIngester($id: ID!, $input: [EditInput!]!) {
        ingestionCsvFieldPatch(id: $id, input: $input){
          ingestion_running
        }
      }
      `,
      variables: CSV_FEED_INGESTER_TO_STOP
    });
    expect(stopSingleColumnCsvFeedsIngesterQueryResult?.data?.ingestionCsvFieldPatch?.ingestion_running).toBeFalsy();
  });

  it('should update the CSV feeds ingester', async () => {
    const CSV_FEED_INGESTER_TO_UPDATE = {
      id: singleColumnCsvFeedIngesterId,
      input: {
        key: 'name',
        value: ['Single column CSV feed ingester'],
      }
    };
    const stopSingleColumnCsvFeedsIngesterQueryResult = await queryAsAdmin({
      query: gql`
      mutation stopSingleColumnCsvFeedsIngester($id: ID!, $input: [EditInput!]!) {
        ingestionCsvFieldPatch(id: $id, input: $input){
          name
        }
      }
      `,
      variables: CSV_FEED_INGESTER_TO_UPDATE
    });
    expect(stopSingleColumnCsvFeedsIngesterQueryResult?.data?.ingestionCsvFieldPatch?.name).toBe('Single column CSV feed ingester');
  });

  it('should reset state of CSV feeds ingester', async () => {
    // shortcut to set a hash that is defined
    const patch = { current_state_hash: 'bbbbbbbbbbbbbbbbbb', added_after_start: utcDate() };
    const result = await patchCsvIngestion(testContext, SYSTEM_USER, singleColumnCsvFeedIngesterId, patch);
    expect(result.current_state_hash).toBe('bbbbbbbbbbbbbbbbbb');

    const CSV_FEED_INGESTER_RESET = {
      id: singleColumnCsvFeedIngesterId,
    };
    const resetStateQueryResult = await queryAsAdminWithSuccess({
      query: gql`
          mutation ingestionCsvResetState($id: ID!) {
              ingestionCsvResetState(id: $id){
                  id
                  current_state_hash
              }
          }
      `,
      variables: CSV_FEED_INGESTER_RESET
    });
    expect(resetStateQueryResult?.data?.ingestionCsvFieldPatch?.current_state_hash).toBeUndefined();
  });

  it('should fail to delete the mapper used by the ingester', async () => {
    const deleteResult = await queryAsAdmin({
      query: gql`
        mutation CsvMapperDelete($id: ID!) {
          csvMapperDelete(id: $id)
        }
      `,
      variables: { id: singleColumnCsvMapperId },
    });
    const { errors } = deleteResult;
    expect(errors).toBeDefined();
    expect(errors?.[0].message).toBe('Cannot delete this CSV Mapper: it is used by one or more IngestionCsv ingester(s)');
  });

  it('should delete the CSV feeds ingester', async () => {
    const CSV_FEED_INGESTER_TO_DELETE = {
      id: singleColumnCsvFeedIngesterId,
    };
    const deleteSingleColumnCsvFeedsIngesterQueryResultSingleColumnCsvFeedsIngesterQueryResult = await queryAsAdmin({
      query: gql`
      mutation deleteSingleColumnCsvFeedsIngesterQueryResultSingleColumnCsvFeedsIngester($id: ID!) {
        ingestionCsvDelete(id: $id)
      }
      `,
      variables: CSV_FEED_INGESTER_TO_DELETE
    });
    expect(deleteSingleColumnCsvFeedsIngesterQueryResultSingleColumnCsvFeedsIngesterQueryResult.data?.ingestionCsvDelete).toBe(singleColumnCsvFeedIngesterId);
  });

  it('should participant forbidden to create csv mapper', async () => {
    const CSV_FEED_INGESTER_TO_CREATE = {
      input: {
        authentication_type: 'none',
        name: 'Single column',
        uri: 'https://lists.blocklist.de/lists/all.txt',
        csv_mapper_id: singleColumnCsvMapperId,
        user_id: USER_PARTICIPATE.id
      }
    };
    await queryAsUserIsExpectedForbidden(
      USER_PARTICIPATE.client,
      { query: gql`
        mutation createSingleColumnCsvFeedsIngester($input: IngestionCsvAddInput!) {
          ingestionCsvAdd(input: $input) {
            id
            entity_type
            ingestion_running
          }
        },
      `,
      variables: CSV_FEED_INGESTER_TO_CREATE
      },
      'CSVMAPPERS should be required to create csv mapper.'
    );
  });

  it('should participant forbidden to list csv mapper', async () => {
    await queryAsUserIsExpectedForbidden(
      USER_PARTICIPATE.client,
      {
        query: gql`
        query listCsvMappers(
          $first: Int
          $after: ID
          $orderBy: CsvMapperOrdering
          $orderMode: OrderingMode
          $filters: FilterGroup
          $search: String) {
          csvMappers(
            first: $first
            after: $after
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
            search: $search) {
              edges {
                  node {
                      id
                  }
              }
          }
        }
      `
      },
      'CSVMAPPERS should be required to list csv mapper.'
    );
  });
});
