import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import type { GraphQLFormattedError } from 'graphql/error';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { IngestionAuthType, TaxiiVersion } from '../../../src/generated/graphql';
import { ADMIN_USER, queryAsAdmin, testContext } from '../../utils/testQuery';
import { now } from '../../../src/utils/format';
import { findById as findIngestionById, patchTaxiiIngestion } from '../../../src/modules/ingestion/ingestion-taxii-domain';

describe('TAXII ingestion resolver standard behavior', () => {
  let createdTaxiiIngesterId: string;
  it('should create a TAXII ingester', async () => {
    const INGESTER_TO_CREATE = {
      input: {
        authentication_type: IngestionAuthType.Basic,
        authentication_value: 'username:P@ssw0rd!',
        name: 'Taxii ingester for integration test',
        version: TaxiiVersion.V21,
        collection: 'TaxiCollection',
        uri: 'http://taxiserver.invalid'
      }
    };
    const ingesterQueryResult = await queryAsAdminWithSuccess({
      query: gql`
        mutation createTaxiiIngester($input: IngestionTaxiiAddInput!) {
          ingestionTaxiiAdd(input: $input) {
              id
              entity_type
              ingestion_running
          }
        },
    `,
      variables: INGESTER_TO_CREATE
    });
    expect(ingesterQueryResult.data?.ingestionTaxiiAdd.id).toBeDefined();
    createdTaxiiIngesterId = ingesterQueryResult.data?.ingestionTaxiiAdd.id;
  });

  it('should edit a TAXII ingester', async () => {
    const ingesterQueryResult = await queryAsAdminWithSuccess({
      query: gql`
        mutation ingestionTaxiiFieldPatch($id: ID!, $input: [EditInput!]!) {
          ingestionTaxiiFieldPatch(id: $id, input: $input) {
            id
            authentication_type
            authentication_value
          }
        }
      `,
      variables: { id: createdTaxiiIngesterId, input: [{ key: 'authentication_value', value: ['username:P@ssw0rd!'] }] }
    });
    expect(ingesterQueryResult.data?.ingestionTaxiiFieldPatch.id).toBeDefined();
    expect(ingesterQueryResult.data?.ingestionTaxiiFieldPatch.authentication_type).toEqual(IngestionAuthType.Basic);
    expect(ingesterQueryResult.data?.ingestionTaxiiFieldPatch.authentication_value).toEqual('username:P@ssw0rd!');
  });

  it('should reset cursor when a user change the start date', async () => {
    // shortcut to set a cursor that is defined
    const state = { current_state_cursor: 'aaaaaaaaaaaaaaaaaaa', last_execution_date: now() };
    const result = await patchTaxiiIngestion(testContext, ADMIN_USER, createdTaxiiIngesterId, state);
    expect(result.current_state_cursor).toBe('aaaaaaaaaaaaaaaaaaa');

    const ingesterChangeDateResult = await queryAsAdminWithSuccess({
      query: gql`
        mutation ingestionTaxiiFieldPatch($id: ID!, $input: [EditInput!]!) {
          ingestionTaxiiFieldPatch(id: $id, input: $input) {
              id
              current_state_cursor
              added_after_start
          }
        }
      `,
      variables: { id: createdTaxiiIngesterId, input: [{ key: 'added_after_start', value: [now()] }] }
    });
    expect(ingesterChangeDateResult.data?.ingestionTaxiiFieldPatch.id).toBeDefined();

    const ingestionState = await findIngestionById(testContext, ADMIN_USER, createdTaxiiIngesterId);
    expect(ingestionState.id).toBeDefined();
    expect(ingestionState.current_state_cursor).not.toBeDefined();
  });

  it('should edit a TAXII ingester with : in authentication value be refused', async () => {
    const ingesterQueryResult = await queryAsAdmin({
      query: gql`
        mutation ingestionTaxiiFieldPatch($id: ID!, $input: [EditInput!]!) {
          ingestionTaxiiFieldPatch(id: $id, input: $input) {
            id
            authentication_type
            authentication_value
          }
        }
      `,
      variables: { id: createdTaxiiIngesterId, input: { key: 'authentication_value', value: ['user:name:P@ssw0rd!'] } }
    });
    expect(ingesterQueryResult.errors).toBeDefined();
    if (ingesterQueryResult.errors) { // above expect is not taken by eslint
      const error:GraphQLFormattedError = ingesterQueryResult.errors[0];
      expect(error.message).toContain('Username and password cannot have : character.');
    }
  });

  it('should reset state of Taxii ingestion', async () => {
    // shortcut to set a cursor that is defined
    const state = { current_state_cursor: 'bbbbbbbbbbbbbbbbbb', last_execution_date: now() };
    const result = await patchTaxiiIngestion(testContext, ADMIN_USER, createdTaxiiIngesterId, state);
    expect(result.current_state_cursor).toBe('bbbbbbbbbbbbbbbbbb');

    const ingesterQueryResult = await queryAsAdminWithSuccess({
      query: gql`
          mutation ingestionTaxiiResetState($id: ID!) {
              ingestionTaxiiResetState(id: $id) {
                  id
                  added_after_start
                  current_state_cursor
                  ingestion_running
                  updated_at
              }
          }
      `,
      variables: { id: createdTaxiiIngesterId }
    });
    expect(ingesterQueryResult.data?.ingestionTaxiiResetState.id).toBeDefined();
    expect(ingesterQueryResult.data?.ingestionTaxiiResetState.current_state_cursor).toBeUndefined();
  });

  it('should delete a TAXII ingester', async () => {
    const ingesterQueryResult = await queryAsAdminWithSuccess({
      query: gql`
        mutation deleteTaxiiIngester($id: ID!) {
            ingestionTaxiiDelete(id: $id)
        }
      `,
      variables: { id: createdTaxiiIngesterId }
    });
    expect(ingesterQueryResult.data?.ingestionTaxiiDelete).toEqual(createdTaxiiIngesterId);
  });
});
