import { beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, adminQuery, queryAsAdmin, testContext, USER_DISINFORMATION_ANALYST, USER_PARTICIPATE } from '../../utils/testQuery';
import { createUploadFromTestDataFile, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { patchCsvIngestion } from '../../../src/modules/ingestion/ingestion-csv-domain';
import { now } from '../../../src/utils/format';
import { SYSTEM_USER } from '../../../src/utils/access';
import pjson from '../../../package.json';
import { IngestionAuthType, type IngestionCsvAddInput, IngestionCsvMapperType } from '../../../src/generated/graphql';
import { findById as findUserById } from '../../../src/domain/user';
import { regenerateCsvMapperUUID } from '../../../src/modules/ingestion/ingestion-converter';
import type { CsvMapperResolved } from '../../../src/modules/internal/csvMapper/csvMapper-types';

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
  const singleColumnCsvMapperForCsvFeedInline = JSON.stringify({
    has_header: false,
    name: 'Single column CSV mapper',
    separator: ',',
    representations: [{ id: '75c3c21c-0a92-497f-962d-4e6e1a488481', type: 'entity', target: { entity_type: 'IPv4-Addr' }, attributes: [{ key: 'value', column: { column_name: 'A' }, based_on: null }] }],
    skipLineChar: ''
  });

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

  it('should count default groups be one from initialization', async () => {
    const defaultIngestionGroupCountResult = await queryAsUserWithSuccess(USER_DISINFORMATION_ANALYST.client, {
      query: gql`
        query IngestionCsvCreationUserHandlingDefaultGroupForIngestionUsersQuery {
          defaultIngestionGroupCount
        }
      `,
      variables: {}
    });
    expect(defaultIngestionGroupCountResult.data.defaultIngestionGroupCount).toBe(1);
  });

  it('should create a CSV feeds ingester with inline CSV Mapper and auto user', async () => {
    const input : IngestionCsvAddInput = {
      authentication_type: IngestionAuthType.None,
      name: 'Single column inline and auto user',
      uri: 'https://lists.blocklist.de/lists/all.txt',
      csv_mapper: singleColumnCsvMapperForCsvFeedInline,
      csv_mapper_type: IngestionCsvMapperType.Inline,
      automatic_user: true,
      user_id: '[F] Single column inline and auto user'
    };

    const createSingleColumnCsvFeedsIngesterQueryResult = await queryAsUserWithSuccess(USER_DISINFORMATION_ANALYST.client, {
      query: gql`
      mutation createSingleColumnCsvFeedsIngester($input: IngestionCsvAddInput!) {
        ingestionCsvAdd(input: $input) {
          id
          entity_type
          csv_mapper_type
          ingestion_running
          user_id
        }
      },
      `,
      variables: { input }
    });
    const csvFeedIngester = createSingleColumnCsvFeedsIngesterQueryResult?.data?.ingestionCsvAdd;
    expect(csvFeedIngester.id).toBeDefined();
    expect(csvFeedIngester.csv_mapper_type).toBe('inline');
    expect(csvFeedIngester.entity_type).toBe('IngestionCsv');
    expect(csvFeedIngester.ingestion_running).toBeFalsy();

    const userIdCreated = csvFeedIngester.user_id;
    const createdUser = await findUserById(testContext, ADMIN_USER, userIdCreated);
    expect(createdUser.name).toBe('[F] Single column inline and auto user');
    expect(createdUser.user_email).toContain('@opencti.invalid');
    // Delete just created user
    await adminQuery({
      query: DELETE_USER_QUERY,
      variables: { id: createdUser.id },
    });
    // Verify no longer found
    const queryResult = await adminQuery({ query: READ_USER_QUERY, variables: { id: createdUser.id } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).toBeNull();
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

  it('should add auto user and update CSV feeds ingester with it', async () => {
    const CSV_FEED_AUTO_USER_UPDATE = {
      id: singleColumnCsvFeedIngesterId,
      input: {
        user_name: 'AutoUser',
        confidence_level: 86
      }
    };
    const updateCsvFeedWithAutoUserResult = await queryAsAdminWithSuccess({
      query: gql`
          mutation updateCsvFeedWithAutoUser($id: ID!, $input: IngestionCsvAddAutoUserInput!) {
              ingestionCsvAddAutoUser(id: $id, input: $input){
                  id
                  user {
                      id
                      name
                  }
              }
          }
      `,
      variables: CSV_FEED_AUTO_USER_UPDATE
    });
    expect(updateCsvFeedWithAutoUserResult?.data?.ingestionCsvAddAutoUser?.user?.name).toBe('AutoUser');
    // Delete just created user
    await adminQuery({
      query: DELETE_USER_QUERY,
      variables: { id: updateCsvFeedWithAutoUserResult?.data?.ingestionCsvAddAutoUser?.user?.id },
    });
    // Verify no longer found
    const queryResult = await adminQuery({ query: READ_USER_QUERY, variables: { id: updateCsvFeedWithAutoUserResult?.data?.ingestionCsvAddAutoUser?.user?.id } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).toBeNull();
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

  it('should regenerate UUID of the CSVMapper', async () => {
    const data: CsvMapperResolved = {
      name: 'C2IntelFeeds',
      has_header: true,
      separator: ',',
      skipLineChar: '',
      representations: [
        {
          id: 'cd610730-daa2-4d97-ba12-e277b74569d3',
          type: 'entity',
          target: {
            entity_type: 'IPv4-Addr',
            column_based: null
          },
          attributes: [
            {
              key: 'value',
              column: {
                column_name: 'A',
                configuration: null
              },
              based_on: null
            },
            {
              key: 'x_opencti_description',
              column: {
                column_name: 'B',
                configuration: null
              },
              based_on: null
            }
          ]
        },
        {
          id: '90ab48b0-88ab-4165-b8e8-9232e6cfa566',
          type: 'entity',
          target: {
            entity_type: 'Autonomous-System',
            column_based: null
          },
          attributes: [
            {
              key: 'number',
              column: {
                column_name: 'C',
                configuration: null
              },
              based_on: null
            }
          ]
        },
        {
          id: '4c7165ef-12bd-48f0-aaf2-645d2186da0d',
          type: 'entity',
          target: {
            entity_type: 'Kill-Chain-Phase',
            column_based: null
          },
          attributes: [
            {
              key: 'kill_chain_name',
              column: {
                column_name: 'E',
                configuration: null
              },
              based_on: null
            },
            {
              key: 'phase_name',
              column: {
                column_name: 'E',
                configuration: null
              },
              based_on: null
            },
            {
              key: 'x_opencti_order',
              column: {
                column_name: 'I',
                configuration: null
              },
              based_on: null
            }
          ]
        },
        {
          id: '6cac2022-04bf-4b5a-b03f-0d2aa878609e',
          type: 'entity',
          target: {
            entity_type: 'Report',
            column_based: null
          },
          attributes: [
            {
              key: 'name',
              column: {
                column_name: 'D',
                configuration: null
              },
              based_on: null
            },
            {
              key: 'published',
              column: {
                column_name: 'E',
                configuration: {
                  pattern_date: 'DD.MM.YYYY',
                  separator: null
                }
              },
              default_values: [
                {
                  id: '2025-06-15T22:00:00.000Z',
                  name: '2025-06-15T22:00:00.000Z'
                }
              ],
              based_on: null
            }
          ]
        },
        {
          id: 'e05fe3ac-1f15-49c2-bdb7-9062a6beb5aa',
          type: 'relationship',
          target: {
            entity_type: 'belongs-to',
            column_based: null
          },
          attributes: [
            {
              key: 'from',
              column: null,
              based_on: {
                representations: [
                  'cd610730-daa2-4d97-ba12-e277b74569d3'
                ]
              }
            },
            {
              key: 'to',
              column: null,
              based_on: {
                representations: [
                  '90ab48b0-88ab-4165-b8e8-9232e6cfa566'
                ]
              }
            },
            {
              key: 'killChainPhases',
              column: {
                column_name: null,
                configuration: {
                  pattern_date: null,
                  separator: ','
                }
              },
              based_on: {
                representations: [
                  '4c7165ef-12bd-48f0-aaf2-645d2186da0d'
                ]
              }
            }
          ]
        }
      ],
      id: '1f919f34-b610-40d6-b681-053cdb2fb026'
    } as unknown as CsvMapperResolved;
    const extractId = data.representations.map((r) => r.id);
    const test = regenerateCsvMapperUUID(data);
    // We verify that at least each id is different after regenerating UUID.
    test.representations.forEach((r) => {
      expect(extractId.includes(r.id)).toBeFalsy();
      r.attributes.forEach((attr) => {
        (attr?.based_on?.representations ?? []).forEach((rep) => {
          expect(rep.includes(r.id)).toBeFalsy();
        });
      });
    });
  });

  it('should duplicate with same CSV Mapper ID as we are link to an existing CSVMapper Id', async () => {
    const CSV_FEED_INGESTER_TO_CREATE = {
      input: {
        authentication_type: 'none',
        name: 'Single column',
        uri: 'https://lists.blocklist.de/lists/all.txt',
        csv_mapper_id: singleColumnCsvMapperId,
        user_id: ADMIN_USER.id,
        csv_mapper_type: 'id'
      }
    };
    const createCsvFeedWithId = await queryAsAdmin({
      query: gql`
        mutation createSingleColumnCsvFeedsIngester($input: IngestionCsvAddInput!) {
          ingestionCsvAdd(input: $input) {
            id
            entity_type
            ingestion_running
            csvMapper {
              id
            }
          }
        },
      `,
      variables: CSV_FEED_INGESTER_TO_CREATE
    });
    const csvFeedId = createCsvFeedWithId?.data?.ingestionCsvAdd?.id;
    const csvMapperId = createCsvFeedWithId?.data?.ingestionCsvAdd?.csvMapper.id;

    const getCsvFeedForDuplication = await queryAsAdmin({
      query: gql`
        query ingestionCsv($id: String!) {
          ingestionCsv(id: $id) {
            id
            duplicateCsvMapper {
              id
            }
          }
        },
      `,
      variables: {
        id: csvFeedId
      }
    });
    expect(getCsvFeedForDuplication?.data?.ingestionCsv.duplicateCsvMapper.id).toEqual(csvMapperId);
  });

  it('should duplicate with different CSVMapperId as we inline CSVMapper', async () => {
    const input : IngestionCsvAddInput = {
      authentication_type: IngestionAuthType.None,
      name: 'Single column inline and auto user',
      uri: 'https://lists.blocklist.de/lists/all.txt',
      csv_mapper: singleColumnCsvMapperForCsvFeedInline,
      csv_mapper_type: IngestionCsvMapperType.Inline,
      user_id: ADMIN_USER.id
    };
    const createCsvFeed = await queryAsAdmin({
      query: gql`
        mutation createSingleColumnCsvFeedsIngester($input: IngestionCsvAddInput!) {
          ingestionCsvAdd(input: $input) {
            id
            entity_type
            ingestion_running
            csvMapper {
              id
            }
          }
        },
      `,
      variables: { input }
    });
    const csvFeedId = createCsvFeed?.data?.ingestionCsvAdd?.id;
    const csvMapperId = createCsvFeed?.data?.ingestionCsvAdd?.csvMapper.id;

    const getCsvFeedForDuplication = await queryAsAdmin({
      query: gql`
        query ingestionCsv($id: String!) {
          ingestionCsv(id: $id) {
            id
            duplicateCsvMapper {
              id
            }
          }
        },
      `,
      variables: {
        id: csvFeedId
      }
    });
    expect(csvMapperId).not.toEqual(getCsvFeedForDuplication?.data?.ingestionCsv.duplicateCsvMapper.id);
  });
});
