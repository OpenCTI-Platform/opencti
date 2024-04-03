import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import type { GraphQLFormattedError } from 'graphql/error';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { TaxiiAuthType, TaxiiVersion } from '../../../src/generated/graphql';
import { queryAsAdmin } from '../../utils/testQuery';

describe('TAXII ingestion resolver standard behavior', () => {
  let createdTaxiiIngesterId: string;
  it('should create a TAXII ingester', async () => {
    const INGESTER_TO_CREATE = {
      input: {
        authentication_type: TaxiiAuthType.Basic,
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
    expect(ingesterQueryResult.data?.ingestionTaxiiFieldPatch.authentication_type).toEqual(TaxiiAuthType.Basic);
    expect(ingesterQueryResult.data?.ingestionTaxiiFieldPatch.authentication_value).toEqual('username:P@ssw0rd!');
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
