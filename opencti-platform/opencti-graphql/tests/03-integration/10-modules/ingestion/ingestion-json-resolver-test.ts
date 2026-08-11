import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER } from '../../../utils/testQuery';
import { createUploadFromTestDataFile, queryAsAdmin, queryAsAdminWithSuccess } from '../../../utils/testQueryHelper';
import { IngestionAuthType } from '../../../../src/generated/graphql';

// Minimal JSON mapper representations - creates a Domain-Name entity from a path
const MINIMAL_REPRESENTATIONS = JSON.stringify([
  {
    id: 'b1a2c3d4-0000-0000-0000-000000000001',
    type: 'entity',
    target: { entity_type: 'Domain-Name', path: '$[*]' },
    attributes: [{ mode: 'simple', key: 'value', attr_path: { path: '$.domain' } }],
  },
]);

describe('JSON ingestion resolver — authentication encryption', () => {
  let jsonMapperId: string;
  let jsonIngestionId: string;

  beforeAll(async () => {
    // Create a JSON mapper to use as dependency
    const result = await queryAsAdminWithSuccess({
      query: gql`
        mutation createJsonMapperForIngestionTest($input: JsonMapperAddInput!) {
          jsonMapperAdd(input: $input) {
            id
          }
        }
      `,
      variables: {
        input: {
          name: 'JSON mapper for ingestion auth test',
          representations: MINIMAL_REPRESENTATIONS,
        },
      },
    });
    jsonMapperId = result.data?.jsonMapperAdd?.id;
    expect(jsonMapperId).toBeDefined();
  });

  afterAll(async () => {
    // Cleanup ingestion if still present
    if (jsonIngestionId) {
      await queryAsAdmin({
        query: gql`mutation deleteJsonIngestionTest($id: ID!) { ingestionJsonDelete(id: $id) }`,
        variables: { id: jsonIngestionId },
      });
    }
    // Cleanup JSON mapper
    if (jsonMapperId) {
      await queryAsAdmin({
        query: gql`mutation deleteJsonMapperTest($id: ID!) { jsonMapperDelete(id: $id) }`,
        variables: { id: jsonMapperId },
      });
    }
  });

  it('should create a JSON ingestion with bearer auth and mask value on create response', async () => {
    // Covers: addIngestionJson encrypt block (ingestion-json-domain.ts)
    // Covers: IngestionJson.authentication_value field resolver (ingestion-json-resolver.ts)
    const result = await queryAsAdminWithSuccess({
      query: gql`
        mutation createJsonIngestionWithAuth($input: IngestionJsonAddInput!) {
          ingestionJsonAdd(input: $input) {
            id
            name
            authentication_type
            authentication_value
          }
        }
      `,
      variables: {
        input: {
          name: 'JSON ingestion with bearer auth',
          uri: 'http://jsonserver.invalid/api/data',
          authentication_type: IngestionAuthType.Bearer,
          authentication_value: 'my-secret-json-bearer-token',
          json_mapper_id: jsonMapperId,
          user_id: ADMIN_USER.id,
          scheduling_period: 'PT1H',
          verb: 'get',
        },
      },
    });
    const created = result.data?.ingestionJsonAdd;
    expect(created.id).toBeDefined();
    jsonIngestionId = created.id;
    // Value must be masked — bearer masking returns 'undefined'
    expect(created.authentication_value).not.toBe('my-secret-json-bearer-token');
    expect(created.authentication_value).toBe('undefined');
  });

  it('should read a JSON ingestion and return masked authentication_value via field resolver', async () => {
    // Covers: ingestionJson query + IngestionJson.authentication_value field resolver
    // Covers: findById (ingestion-json-domain.ts)
    const result = await queryAsAdminWithSuccess({
      query: gql`
        query readJsonIngestionAuth($id: String!) {
          ingestionJson(id: $id) {
            id
            authentication_type
            authentication_value
          }
        }
      `,
      variables: { id: jsonIngestionId },
    });
    const ingestion = result.data?.ingestionJson;
    expect(ingestion.id).toBe(jsonIngestionId);
    expect(ingestion.authentication_type).toBe(IngestionAuthType.Bearer);
    // Field resolver must decrypt then mask — NOT return raw encrypted base64
    expect(ingestion.authentication_value).toBe('undefined');
  });

  it('should patch authentication_value and return masked value', async () => {
    // Covers: ingestionJsonFieldPatch → ingestionJsonEditField decrypt+re-encrypt (ingestion-json-domain.ts)
    // Covers: IngestionJson.authentication_value field resolver on mutation response
    const result = await queryAsAdminWithSuccess({
      query: gql`
        mutation patchJsonIngestionAuth($id: ID!, $input: [EditInput!]!) {
          ingestionJsonFieldPatch(id: $id, input: $input) {
            id
            authentication_value
          }
        }
      `,
      variables: {
        id: jsonIngestionId,
        input: [{ key: 'authentication_value', value: ['updated-bearer-token'] }],
      },
    });
    const patched = result.data?.ingestionJsonFieldPatch;
    expect(patched.id).toBe(jsonIngestionId);
    expect(patched.authentication_value).toBe('undefined');
  });

  it('should edit a JSON ingestion via ingestionJsonEdit and encrypt authentication_value', async () => {
    // Covers: editIngestionJson decrypt+encrypt block (ingestion-json-domain.ts)
    const result = await queryAsAdminWithSuccess({
      query: gql`
        mutation editJsonIngestion($id: ID!, $input: IngestionJsonAddInput!) {
          ingestionJsonEdit(id: $id, input: $input) {
            id
            authentication_type
            authentication_value
          }
        }
      `,
      variables: {
        id: jsonIngestionId,
        input: {
          name: 'JSON ingestion with bearer auth',
          uri: 'http://jsonserver.invalid/api/data',
          authentication_type: IngestionAuthType.Bearer,
          authentication_value: 'replaced-bearer-token',
          json_mapper_id: jsonMapperId,
          user_id: ADMIN_USER.id,
          scheduling_period: 'PT1H',
          verb: 'get',
        },
      },
    });
    const edited = result.data?.ingestionJsonEdit;
    expect(edited.id).toBe(jsonIngestionId);
    // Value must be masked via field resolver — bearer masking returns 'undefined'
    expect(edited.authentication_value).toBe('undefined');
  });

  it('should create a JSON ingestion with basic auth and mask value', async () => {
    // Covers: addIngestionJson encrypt block with basic auth type
    const result = await queryAsAdminWithSuccess({
      query: gql`
        mutation createJsonIngestionBasicAuth($input: IngestionJsonAddInput!) {
          ingestionJsonAdd(input: $input) {
            id
            authentication_type
            authentication_value
          }
        }
      `,
      variables: {
        input: {
          name: 'JSON ingestion with basic auth',
          uri: 'http://jsonserver.invalid/api/data',
          authentication_type: IngestionAuthType.Basic,
          authentication_value: 'user:P@ssw0rd',
          json_mapper_id: jsonMapperId,
          user_id: ADMIN_USER.id,
          scheduling_period: 'PT1H',
          verb: 'get',
        },
      },
    });
    const created = result.data?.ingestionJsonAdd;
    expect(created.id).toBeDefined();
    expect(created.authentication_type).toBe(IngestionAuthType.Basic);
    // Basic auth masking returns 'username:undefined'
    expect(created.authentication_value).toBe('user:undefined');

    // Cleanup this extra ingestion
    await queryAsAdmin({
      query: gql`mutation deleteJsonIngestionBasic($id: ID!) { ingestionJsonDelete(id: $id) }`,
      variables: { id: created.id },
    });
  });

  it('should delete the JSON ingestion', async () => {
    const result = await queryAsAdminWithSuccess({
      query: gql`
        mutation deleteJsonIngestionTest($id: ID!) {
          ingestionJsonDelete(id: $id)
        }
      `,
      variables: { id: jsonIngestionId },
    });
    expect(result.data?.ingestionJsonDelete).toBe(jsonIngestionId);
    jsonIngestionId = ''; // mark as deleted so afterAll skips it
  });
});

describe('JSON ingestion resolver — configuration export / import', () => {
  const IMPORT_MUTATION = gql`
    mutation jsonFeedAddInputFromImport($file: Upload!) {
      ingestionJsonAddInputFromImport(file: $file) {
        name
        description
        scheduling_period
        uri
        verb
        ssl_verify
        headers {
          name
          value
        }
        authentication_type
        jsonMapper {
          id
          name
        }
      }
    }
  `;
  const DELETE_MAPPER_MUTATION = gql`mutation deleteJsonMapperFromImport($id: ID!) { jsonMapperDelete(id: $id) }`;

  let exportMapperId: string;
  let exportIngestionId: string;
  let importedMapperId: string;

  beforeAll(async () => {
    const mapperResult = await queryAsAdminWithSuccess({
      query: gql`
        mutation createJsonMapperForExportTest($input: JsonMapperAddInput!) {
          jsonMapperAdd(input: $input) {
            id
          }
        }
      `,
      variables: {
        input: {
          name: 'JSON mapper for export test',
          representations: MINIMAL_REPRESENTATIONS,
        },
      },
    });
    exportMapperId = mapperResult.data?.jsonMapperAdd?.id;
    expect(exportMapperId).toBeDefined();

    const ingestionResult = await queryAsAdminWithSuccess({
      query: gql`
        mutation createJsonIngestionForExportTest($input: IngestionJsonAddInput!) {
          ingestionJsonAdd(input: $input) {
            id
          }
        }
      `,
      variables: {
        input: {
          name: 'JSON feed for export test',
          description: 'JSON feed export description',
          uri: 'http://jsonserver.invalid/api/export',
          authentication_type: IngestionAuthType.None,
          json_mapper_id: exportMapperId,
          user_id: ADMIN_USER.id,
          scheduling_period: 'PT1H',
          verb: 'get',
          headers: [
            { name: 'Accept', value: 'application/json' },
            { name: 'Authorization', value: 'Bearer super-secret-token' },
          ],
        },
      },
    });
    exportIngestionId = ingestionResult.data?.ingestionJsonAdd?.id;
    expect(exportIngestionId).toBeDefined();
  });

  afterAll(async () => {
    if (exportIngestionId) {
      await queryAsAdmin({
        query: gql`mutation deleteJsonIngestionExportTest($id: ID!) { ingestionJsonDelete(id: $id) }`,
        variables: { id: exportIngestionId },
      });
    }
    if (exportMapperId) {
      await queryAsAdmin({ query: DELETE_MAPPER_MUTATION, variables: { id: exportMapperId } });
    }
    if (importedMapperId) {
      await queryAsAdmin({ query: DELETE_MAPPER_MUTATION, variables: { id: importedMapperId } });
    }
  });

  it('should generate a self-contained export configuration with the embedded mapper', async () => {
    // Covers: jsonFeedExport (ingestion-json-domain.ts)
    // Covers: IngestionJson.toConfigurationExport field resolver
    const result = await queryAsAdminWithSuccess({
      query: gql`
        query queryJsonFeedExport($id: String!) {
          ingestionJson(id: $id) {
            name
            toConfigurationExport
          }
        }
      `,
      variables: { id: exportIngestionId },
    });
    const exported = JSON.parse(result.data?.ingestionJson.toConfigurationExport);
    expect(exported.type).toBe('jsonFeeds');
    expect(exported.openCTI_version).toBeDefined();
    expect(exported.configuration).toMatchObject({
      name: 'JSON feed for export test',
      description: 'JSON feed export description',
      uri: 'http://jsonserver.invalid/api/export',
      verb: 'get',
      scheduling_period: 'PT1H',
      // Credentials are platform-specific and never exported.
      authentication_value: '',
    });
    // Covers: sanitizeExportedHeaders — sensitive header values are blanked,
    // non-sensitive ones are exported as-is.
    expect(exported.configuration.headers).toEqual([
      { name: 'Accept', value: 'application/json' },
      { name: 'Authorization', value: '' },
    ]);
    expect(exported.configuration.json_mapper.name).toBe('JSON mapper for export test');
    expect(exported.configuration.json_mapper.representations).toHaveLength(1);
    expect(exported.configuration.json_mapper.representations[0].target.entity_type).toBe('Domain-Name');
  });

  it('should import a configuration and create the embedded mapper when it does not exist', async () => {
    // Covers: jsonFeedAddInputFromImport mapper creation branch (ingestion-json-domain.ts)
    // Covers: createJsonMapperFromConfiguration (jsonMapper-domain.ts)
    const upload = await createUploadFromTestDataFile('jsonFeed/test-json-feed.json', 'test-json-feed.json', 'application/json');
    const result = await queryAsAdminWithSuccess({
      query: IMPORT_MUTATION,
      variables: { file: upload },
    });
    const imported = result.data?.ingestionJsonAddInputFromImport;
    expect(imported).toMatchObject({
      name: 'jsonFeedAuto',
      description: 'Imported JSON feed',
      scheduling_period: 'PT1H',
      uri: 'http://jsonserver.invalid/api/data',
      verb: 'get',
      ssl_verify: true,
      headers: [{ name: 'Accept', value: 'application/json' }],
    });
    expect(imported.jsonMapper.name).toBe('JSON mapper from feed import test');
    expect(imported.jsonMapper.id).toBeDefined();
    importedMapperId = imported.jsonMapper.id;
  });

  it('should reuse the existing mapper when importing the same configuration again', async () => {
    // Covers: jsonFeedAddInputFromImport mapper reuse branch (ingestion-json-domain.ts)
    const upload = await createUploadFromTestDataFile('jsonFeed/test-json-feed.json', 'test-json-feed.json', 'application/json');
    const result = await queryAsAdminWithSuccess({
      query: IMPORT_MUTATION,
      variables: { file: upload },
    });
    const imported = result.data?.ingestionJsonAddInputFromImport;
    expect(imported.jsonMapper.id).toBe(importedMapperId);
  });

  it('should refuse a configuration exported by an incompatible platform version', async () => {
    // Covers: the version guard of jsonFeedAddInputFromImport
    const upload = await createUploadFromTestDataFile('jsonFeed/test-json-feed-outdated.json', 'test-json-feed-outdated.json', 'application/json');
    const result = await queryAsAdmin({
      query: IMPORT_MUTATION,
      variables: { file: upload },
    });
    expect(result.errors).toBeDefined();
    if (result.errors) {
      expect(result.errors[0].message).toContain('Invalid version of the platform');
    }
  });

  it('should refuse a configuration without an embedded mapper', async () => {
    // Covers: the missing mapper guard of jsonFeedAddInputFromImport
    const upload = await createUploadFromTestDataFile('jsonFeed/test-json-feed-no-mapper.json', 'test-json-feed-no-mapper.json', 'application/json');
    const result = await queryAsAdmin({
      query: IMPORT_MUTATION,
      variables: { file: upload },
    });
    expect(result.errors).toBeDefined();
    if (result.errors) {
      expect(result.errors[0].message).toContain('missing embedded JSON mapper');
    }
  });
});
