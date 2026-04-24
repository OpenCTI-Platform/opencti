import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER } from '../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { IngestionAuthType } from '../../../src/generated/graphql';

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
    // Value must be masked — must NOT return the plain text token
    expect(created.authentication_value).not.toBe('my-secret-json-bearer-token');
    expect(created.authentication_value).toMatch(/\*/);
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
    expect(ingestion.authentication_value).toMatch(/\*/);
    expect(ingestion.authentication_value).not.toMatch(/^[A-Za-z0-9+/]+=*$/); // must not be raw base64
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
    expect(patched.authentication_value).toMatch(/\*/);
    expect(patched.authentication_value).not.toBe('updated-bearer-token');
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
    // Value must be masked via field resolver
    expect(edited.authentication_value).toMatch(/\*/);
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
    expect(created.authentication_value).toMatch(/\*/);
    expect(created.authentication_value).not.toBe('user:P@ssw0rd');

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
