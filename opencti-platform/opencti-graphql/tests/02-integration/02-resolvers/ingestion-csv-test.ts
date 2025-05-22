import { beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin, testContext, USER_DISINFORMATION_ANALYST, USER_PARTICIPATE } from '../../utils/testQuery';
import { createUploadFromTestDataFile, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { patchCsvIngestion } from '../../../src/modules/ingestion/ingestion-csv-domain';
import { now } from '../../../src/utils/format';
import { SYSTEM_USER } from '../../../src/utils/access';
import pjson from '../../../package.json';

describe('CSV ingestion resolver standard behavior', () => {
  let singleColumnCsvMapperId = '';
  let singleColumnCsvFeedIngesterId = '';
  const singleColumnCsvMapper = {
    input: {
      has_header: false,
      name: 'Single column CSV mapper',
      separator: ',',
      representations: '[{"id":"75c3c21c-0a92-497f-962d-4e6e1a488481","type":"entity","target":{"entity_type":"IPv4-Addr"},"attributes":[{"key":"value","column":{"column_name":"A"},"based_on":null}]}]',
      skipLineChar: ''
    }
  };

  beforeAll(async () => {
    const SINGLE_COLUMN_CSV_MAPPER = singleColumnCsvMapper;

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
    const createSingleColumnCsvFeedsWithInlineMapperIngesterQueryResult = await queryAsAdmin({
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
    singleColumnCsvFeedIngesterId = createSingleColumnCsvFeedsWithInlineMapperIngesterQueryResult?.data?.ingestionCsvAdd?.id;
    expect(singleColumnCsvFeedIngesterId).toBeDefined();
    expect(createSingleColumnCsvFeedsWithInlineMapperIngesterQueryResult?.data?.ingestionCsvAdd?.entity_type).toBe('IngestionCsv');
    expect(createSingleColumnCsvFeedsWithInlineMapperIngesterQueryResult?.data?.ingestionCsvAdd?.ingestion_running).toBeFalsy();
  });

  it('should create a CSV feeds ingester with inline CSV Mapper', async () => {
    const CSV_FEED_INGESTER_TO_CREATE = {
      input: {
        authentication_type: 'none',
        name: 'Single column',
        uri: 'https://lists.blocklist.de/lists/all.txt',
        csv_mapper: JSON.stringify(singleColumnCsvMapper),
        csv_mapper_type: 'inline',
        user_id: ADMIN_USER.id
      }
    };
    const createSingleColumnCsvFeedsIngesterQueryResult = await queryAsUserWithSuccess(USER_DISINFORMATION_ANALYST.client, {
      query: gql`
      mutation createSingleColumnCsvFeedsIngester($input: IngestionCsvAddInput!) {
        ingestionCsvAdd(input: $input) {
        id
        entity_type
        csv_mapper_type
        ingestion_running
          }
      },
      `,
      variables: CSV_FEED_INGESTER_TO_CREATE
    });
    const csvFeedIngester = createSingleColumnCsvFeedsIngesterQueryResult?.data?.ingestionCsvAdd;
    expect(csvFeedIngester.id).toBeDefined();
    expect(csvFeedIngester.csv_mapper_type).toBe('inline');
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
    const patch = { current_state_hash: 'bbbbbbbbbbbbbbbbbb', added_after_start: now() };
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
    expect(errors?.[0].message).toBe('Cannot delete this CSV Mapper: it is used by one or more IngestionCsv feed(s)');
  });

  it('should generate correct export configuration', async () => {
    const QUERY_CSV_FEED = gql(`
      query QueryCSVFeed($id: String!) {
        ingestionCsv(id: $id) {
          id
          name
          toConfigurationExport
        }
      }
    `);
    const { data } = await queryAsAdmin({
      query: QUERY_CSV_FEED,
      variables: { id: singleColumnCsvFeedIngesterId }
    });
    expect(data?.ingestionCsv.id).toBe(singleColumnCsvFeedIngesterId);
    expect(data?.ingestionCsv.name).toBe('Single column CSV feed ingester');
    const csvFeedIngestion = JSON.parse(data?.ingestionCsv.toConfigurationExport);
    expect(csvFeedIngestion.type).toBe('csvFeeds');
    expect(csvFeedIngestion.openCTI_version).toBe(pjson.version);
    expect(csvFeedIngestion.configuration).toBeDefined();
    expect(csvFeedIngestion.configuration.name).toBe('Single column CSV feed ingester');
    expect(csvFeedIngestion.configuration.uri).toBe('https://lists.blocklist.de/lists/all.txt');
    expect(csvFeedIngestion.configuration.csv_mapper_type).toBe('inline');
    expect(csvFeedIngestion.configuration.authentication_type).toBe('none');
    expect(csvFeedIngestion.configuration.csv_mapper.configuration).toBeDefined();
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

  it('should test a json file against import', async () => {
    const upload = await createUploadFromTestDataFile('csvFeed/test-csv-feed.json', 'test-csv-feed.json', 'application/json');
    const TEST_MUTATION = gql`
      query CsvFeedAddInputFromImport($file: Upload!) {
        csvFeedAddInputFromImport(file: $file){
          authentication_type
          name
          csvMapper {
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: TEST_MUTATION,
      variables: {
        file: upload,
      },
    });
    expect(queryResult.data?.csvFeedAddInputFromImport).toBeDefined();
    expect(queryResult.data?.csvFeedAddInputFromImport.csvMapper).toBeDefined();
    expect(queryResult.data?.csvFeedAddInputFromImport.csvMapper.name).toBe('Inline CSV Feed');
    expect(queryResult.data?.csvFeedAddInputFromImport.name).toBe('Test name');
  });
});
